package fecquic

import (
	"encoding/binary"
	"errors"

	"github.com/quic-go/quic-go/internal/fecwire"
)

// FileHeader is sent once on a reliable QUIC stream before any FEC symbols.
// Layout:
//
//	TYPE     1B   fecwire.TypeQFECHeader
//	FILESIZE u64  exact byte length
//	CHUNK    u32  bytes per symbol (L)
//	RX_DDL   u32  receiver ARQ soft deadline in milliseconds
const (
	fileHeaderLen = 1 + 8 + 4 + 4
)

type FileHeader struct {
	FileSize uint64
	ChunkL   uint32
	// RxDDLMS is the receiver soft deadline for ARQ (seen-block idle-from-lastSymAt), in milliseconds.
	// 0 means "not specified" (receiver uses its default).
	RxDDLMS uint32
}

func (h *FileHeader) MarshalBinary() []byte {
	b := make([]byte, fileHeaderLen)
	b[0] = fecwire.TypeQFECHeader
	binary.LittleEndian.PutUint64(b[1:9], h.FileSize)
	binary.LittleEndian.PutUint32(b[9:13], h.ChunkL)
	binary.LittleEndian.PutUint32(b[13:17], h.RxDDLMS)
	return b
}

func (h *FileHeader) UnmarshalBinary(b []byte) error {
	if len(b) < fileHeaderLen {
		return errors.New("short header")
	}
	if b[0] != fecwire.TypeQFECHeader {
		return errors.New("unexpected QFEC header type")
	}
	h.FileSize = binary.LittleEndian.Uint64(b[1:9])
	h.ChunkL = binary.LittleEndian.Uint32(b[9:13])
	h.RxDDLMS = binary.LittleEndian.Uint32(b[13:17])
	return nil
}
