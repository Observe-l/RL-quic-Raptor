package fecquic

import (
	"bytes"
	"testing"
)

func TestFileHeaderRoundtrip(t *testing.T) {
	var sha [32]byte
	for i := range sha {
		sha[i] = byte(i)
	}
	h := FileHeader{Version: 1, FileSize: 123456789, SHA256: sha, ChunkL: 1200}
	b := h.MarshalBinary()
	if len(b) != fileHeaderLen {
		t.Fatalf("len=%d", len(b))
	}
	var h2 FileHeader
	if err := h2.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if h2.Version != 1 || h2.FileSize != h.FileSize || h2.ChunkL != h.ChunkL || !bytes.Equal(h2.SHA256[:], h.SHA256[:]) {
		t.Fatalf("mismatch: %+v vs %+v", h2, h)
	}
}
