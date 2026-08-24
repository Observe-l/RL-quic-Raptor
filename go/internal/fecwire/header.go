package fecwire

import (
	"encoding/binary"
)

// Type values are shared across the QFEC wire records. The transport
// context still determines which record parser is used.
const (
	TypeQFECHeader uint8 = 1
	TypeFECSymbol  uint8 = 2
	TypeACK        uint8 = 3
	TypeNACK       uint8 = 4
	TypeDONE       uint8 = 5
)

type FECHeader struct {
	Type    uint8  // TypeFECSymbol
	BlockID uint32 // per-block counter
	N       uint8
	K       uint8
	SymID   uint8 // 0..N-1 position in codeword
}

// HeaderLen is the fixed FEC symbol header size. The payload occupies the
// remainder of a DATAGRAM and its length is derived from the received
// datagram length. For stream compatibility, the sender/receiver use the
// QFEC file header's ChunkL as the fixed payload size.
const HeaderLen = 1 + 4 + 1 + 1 + 1

func (h *FECHeader) MarshalBinary(b []byte) []byte {
	if len(b) < HeaderLen {
		b = make([]byte, HeaderLen)
	}
	b[0] = h.Type
	binary.LittleEndian.PutUint32(b[1:5], h.BlockID)
	b[5] = h.N
	b[6] = h.K
	b[7] = h.SymID
	return b[:HeaderLen]
}

func (h *FECHeader) UnmarshalBinary(b []byte) bool {
	if len(b) < HeaderLen {
		return false
	}
	h.Type = b[0]
	h.BlockID = binary.LittleEndian.Uint32(b[1:5])
	h.N = b[5]
	h.K = b[6]
	h.SymID = b[7]
	return true
}
