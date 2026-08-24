package fecquic

import (
	"bytes"
	"testing"
)

func TestNackWireRoundtrip(t *testing.T) {
	want := NackNeedMore{
		BlockID:    0x12345678,
		AttemptIdx: 3,
		RecvCount:  25,
	}

	var buf bytes.Buffer
	if err := writeNack(&buf, want); err != nil {
		t.Fatal(err)
	}
	if got, wantLen := buf.Len(), 9; got != wantLen {
		t.Fatalf("NACK length=%d, want %d", got, wantLen)
	}

	typ, value, err := readCtrl(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != arqMsgNACK {
		t.Fatalf("type=%d, want %d", typ, arqMsgNACK)
	}
	got, ok := value.(NackNeedMore)
	if !ok {
		t.Fatalf("decoded value has type %T", value)
	}
	if got != want {
		t.Fatalf("decoded NACK=%+v, want %+v", got, want)
	}
}

func TestAckWireRoundtrip(t *testing.T) {
	want := AckSuccess{
		BlockID: 0x12345678,
	}

	var buf bytes.Buffer
	if err := writeAck(&buf, want); err != nil {
		t.Fatal(err)
	}
	if got, wantLen := buf.Len(), 5; got != wantLen {
		t.Fatalf("ACK length=%d, want %d", got, wantLen)
	}

	typ, value, err := readCtrl(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if typ != arqMsgACK {
		t.Fatalf("type=%d, want %d", typ, arqMsgACK)
	}
	got, ok := value.(AckSuccess)
	if !ok {
		t.Fatalf("decoded value has type %T", value)
	}
	if got != want {
		t.Fatalf("decoded ACK=%+v, want %+v", got, want)
	}
}

func TestARQRepairCountIncludesRStep(t *testing.T) {
	tests := []struct {
		name      string
		k         int
		recvCount int
		rstep     int
		want      int
	}{
		{name: "deficit plus rstep", k: 30, recvCount: 29, rstep: 4, want: 6},
		{name: "large deficit plus rstep", k: 30, recvCount: 3, rstep: 4, want: 32},
		{name: "no deficit still keeps rstep", k: 30, recvCount: 31, rstep: 4, want: 4},
		{name: "negative rstep is clamped", k: 30, recvCount: 29, rstep: -4, want: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := arqRepairCount(tt.k, tt.recvCount, tt.rstep); got != tt.want {
				t.Fatalf("arqRepairCount(%d, %d, %d)=%d, want %d", tt.k, tt.recvCount, tt.rstep, got, tt.want)
			}
		})
	}
}
