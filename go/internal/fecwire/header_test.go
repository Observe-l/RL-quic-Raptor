package fecwire

import "testing"

func TestFECHeaderRoundtrip(t *testing.T) {
	want := FECHeader{
		Type:    TypeFECSymbol,
		BlockID: 0x12345678,
		N:       40,
		K:       30,
		SymID:   31,
	}

	b := want.MarshalBinary(nil)
	if len(b) != 8 {
		t.Fatalf("header length=%d, want 8", len(b))
	}

	var got FECHeader
	if !got.UnmarshalBinary(b) {
		t.Fatal("failed to decode FEC header")
	}
	if got != want {
		t.Fatalf("decoded header=%+v, want %+v", got, want)
	}
}
