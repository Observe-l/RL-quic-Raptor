package fecquic

import "testing"

func TestFileHeaderRoundtrip(t *testing.T) {
	h := FileHeader{FileSize: 123456789, ChunkL: 1200, RxDDLMS: 150}
	b := h.MarshalBinary()
	if len(b) != fileHeaderLen {
		t.Fatalf("len=%d", len(b))
	}
	var h2 FileHeader
	if err := h2.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if h2 != h {
		t.Fatalf("mismatch: %+v vs %+v", h2, h)
	}
}
