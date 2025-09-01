package fecquic

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// FileHeader is sent once on a reliable QUIC stream before any FEC symbols.
// Layout:
//
//	MAGIC    4B   "QFEC"
//	VERSION  u16  0x0001
//	FILESIZE u64  exact byte length
//	SHA256   32B  digest of the original bytes
//	CHUNK    u32  bytes per symbol (L)
//	RESERVED 8B   zeros
const (
	fileHeaderMagic = "QFEC"
	fileHeaderLen   = 4 + 2 + 8 + 32 + 4 + 8
)

type FileHeader struct {
	Version  uint16
	FileSize uint64
	SHA256   [32]byte
	ChunkL   uint32
}

func (h *FileHeader) MarshalBinary() []byte {
	b := make([]byte, fileHeaderLen)
	copy(b[0:4], []byte(fileHeaderMagic))
	binary.LittleEndian.PutUint16(b[4:6], h.Version)
	binary.LittleEndian.PutUint64(b[6:14], h.FileSize)
	copy(b[14:46], h.SHA256[:])
	binary.LittleEndian.PutUint32(b[46:50], h.ChunkL)
	// reserved zeros 50:58
	return b
}

func (h *FileHeader) UnmarshalBinary(b []byte) error {
	if len(b) < fileHeaderLen {
		return errors.New("short header")
	}
	if string(b[0:4]) != fileHeaderMagic {
		return errors.New("bad magic")
	}
	h.Version = binary.LittleEndian.Uint16(b[4:6])
	if h.Version != 1 {
		return errors.New("unsupported version")
	}
	h.FileSize = binary.LittleEndian.Uint64(b[6:14])
	copy(h.SHA256[:], b[14:46])
	h.ChunkL = binary.LittleEndian.Uint32(b[46:50])
	return nil
}

// ComputeSHA256 computes the SHA256 of r, limited to n bytes.
func ComputeSHA256(r io.Reader) ([32]byte, uint64, error) {
	h := sha256.New()
	var buf [64 * 1024]byte
	var nTotal uint64
	for {
		n, err := r.Read(buf[:])
		if n > 0 {
			nTotal += uint64(n)
			_, _ = h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return [32]byte{}, 0, err
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nTotal, nil
}
