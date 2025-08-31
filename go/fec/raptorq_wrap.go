package fec

import (
	"errors"

	rqq "github.com/xssnick/raptorq"
)

// RaptorQWrapper provides a minimal, transport-agnostic wrapper for Systematic RaptorQ.
// Fixed generation params are typically N=32, K=26, L=1500 as per docs, but we
// don’t hardcode here; caller chooses K and L and derives N by providing number of repair.

type RaptorQEncoder struct {
	K int
	L int
	r *rqq.RaptorQ
	e *rqq.Encoder
}

type RaptorQDecoder struct {
	K int
	L int
	r *rqq.RaptorQ
	d *rqq.Decoder
}

// NewRaptorQEncoder creates an encoder for one generation from contiguous payload bytes.
// It expects len(data) <= K*L; the last symbol is padded internally by the library.
func NewRaptorQEncoder(data []byte, K, L int) (*RaptorQEncoder, error) {
	if K <= 0 || L <= 0 {
		return nil, errors.New("bad K or L")
	}
	rq := rqq.NewRaptorQ(uint32(L))
	enc, err := rq.CreateEncoder(data)
	if err != nil {
		return nil, err
	}
	return &RaptorQEncoder{K: K, L: L, r: rq, e: enc}, nil
}

// GenSymbol returns the symbol bytes for a given symbol id.
// For 0 <= id < K, this returns the systematic source symbols.
// For id >= K, this returns repair symbols.
func (e *RaptorQEncoder) GenSymbol(id uint32) []byte {
	return e.e.GenSymbol(id)
}

// BaseSymbolsNum returns K for this generation as reported by the library.
func (e *RaptorQEncoder) BaseSymbolsNum() uint32 { return e.e.BaseSymbolsNum() }

// NewRaptorQDecoder creates a decoder for a generation of given original data size.
func NewRaptorQDecoder(dataSize int, L int) (*RaptorQDecoder, error) {
	if dataSize < 0 || L <= 0 {
		return nil, errors.New("bad dataSize or L")
	}
	rq := rqq.NewRaptorQ(uint32(L))
	dec, err := rq.CreateDecoder(uint32(dataSize))
	if err != nil {
		return nil, err
	}
	// K is derived from params inside the decoder; expose via FastSymbolsNumRequired.
	return &RaptorQDecoder{K: int(dec.FastSymbolsNumRequired()), L: L, r: rq, d: dec}, nil
}

// AddSymbol feeds a symbol with its id. Returns whether decoding can be attempted.
func (d *RaptorQDecoder) AddSymbol(id uint32, data []byte) (bool, error) {
	return d.d.AddSymbol(id, data)
}

// Decode attempts to reconstruct the original payload. On success, returns the exact
// bytes (trimmed by the library to original size).
func (d *RaptorQDecoder) Decode() (bool, []byte, error) {
	return d.d.Decode()
}

// High-level convenience API

// RaptorQEncodeBlock generates N symbols (0..N-1) for a block consisting of up to K*L bytes.
// It returns fec.Packets with Index set to the symbol id and Data set to symbol bytes.
// Data beyond K*L is truncated; if data is shorter, the library pads internally.
func RaptorQEncodeBlock(data []byte, N, K, L int) ([]Packet, error) {
	if N <= 0 || K <= 0 || L <= 0 || K > N {
		return nil, errors.New("bad N/K/L")
	}
	// Clamp data to K*L bytes
	max := K * L
	if len(data) > max {
		data = data[:max]
	}
	enc, err := NewRaptorQEncoder(data, K, L)
	if err != nil {
		return nil, err
	}
	out := make([]Packet, N)
	for i := 0; i < N; i++ {
		out[i] = Packet{Index: i, Data: enc.GenSymbol(uint32(i))}
	}
	return out, nil
}

// RaptorQDecodeBytes decodes a block into the original byte slice of length dataSize (<=K*L).
// Returns ok=false if decoding fails.
func RaptorQDecodeBytes(recv []Packet, N, K, L, dataSize int) ([]byte, bool) {
	if K <= 0 || L <= 0 || dataSize < 0 {
		return nil, false
	}
	dec, err := NewRaptorQDecoder(dataSize, L)
	if err != nil {
		return nil, false
	}
	for _, p := range recv {
		if p.Index < 0 || p.Index >= N {
			continue
		}
		if _, err := dec.AddSymbol(uint32(p.Index), p.Data); err != nil {
			// ignore bad symbol; continue adding
		}
	}
	ok, bytes, err := dec.Decode()
	if err != nil || !ok {
		return nil, false
	}
	return bytes, true
}
