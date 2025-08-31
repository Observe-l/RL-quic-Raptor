package fecwire

import (
	"encoding/binary"
)

// FECScheme identifiers used on the wire.
const (
	SchemeRLC     uint8 = 0
	SchemeRS      uint8 = 1
	SchemePolar   uint8 = 2
	SchemeRaptorQ uint8 = 3
)

type FECHeader struct {
	Version    uint8  // 1
	Scheme     uint8  // 0=RLC,1=RS,2=Polar,3=RaptorQ
	BlockID    uint16 // per-block counter
	N          uint8
	K          uint8
	SymID      uint8  // 0..N-1 position in codeword
	Flags      uint8  // reserved
	PayloadLen uint32 // L bytes (symbol length)
	SeedOrIdx  uint32 // RLC seed or RS column index or reserved
}

const HeaderLen = 1 + 1 + 2 + 1 + 1 + 1 + 1 + 4 + 4

func (h *FECHeader) MarshalBinary(b []byte) []byte {
	if len(b) < HeaderLen {
		b = make([]byte, HeaderLen)
	}
	b[0] = h.Version
	b[1] = h.Scheme
	binary.LittleEndian.PutUint16(b[2:4], h.BlockID)
	b[4] = h.N
	b[5] = h.K
	b[6] = h.SymID
	b[7] = h.Flags
	binary.LittleEndian.PutUint32(b[8:12], h.PayloadLen)
	binary.LittleEndian.PutUint32(b[12:16], h.SeedOrIdx)
	return b[:HeaderLen]
}

func (h *FECHeader) UnmarshalBinary(b []byte) bool {
	if len(b) < HeaderLen {
		return false
	}
	h.Version = b[0]
	h.Scheme = b[1]
	h.BlockID = binary.LittleEndian.Uint16(b[2:4])
	h.N = b[4]
	h.K = b[5]
	h.SymID = b[6]
	h.Flags = b[7]
	h.PayloadLen = binary.LittleEndian.Uint32(b[8:12])
	h.SeedOrIdx = binary.LittleEndian.Uint32(b[12:16])
	return true
}
