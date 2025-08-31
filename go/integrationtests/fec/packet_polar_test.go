package fec_test

import (
	"crypto/rand"
	"testing"

	"github.com/quic-go/quic-go/fec"
)

func TestPacketPolar_EncodeDecode_Simple(t *testing.T) {
	N, K := 32, 24
	R := N - K
	L := 256
	eps := 0.1
	p, err := fec.NewPacketPolarParams(N, K, eps, L)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	// make K random sources
	src := make([][]byte, K)
	for i := range src {
		src[i] = make([]byte, L)
		_, _ = rand.Read(src[i])
	}
	par := fec.PacketPolarEncode(p, src)
	if len(par) != R {
		t.Fatalf("expected %d parity, got %d", R, len(par))
	}
	// simulate receiving K packets: some mix of sources/parities
	recv := make([]fec.Packet, 0, K)
	for i := 0; i < K-2; i++ { // lose 2 sources, use parities
		recv = append(recv, fec.Packet{Index: i, Data: src[i]})
	}
	recv = append(recv, fec.Packet{Index: K + 0, Data: par[0]})
	recv = append(recv, fec.Packet{Index: K + 1, Data: par[1]})
	// decode
	dec, ok := fec.PacketPolarDecode(p, recv)
	if !ok {
		t.Fatalf("decode failed")
	}
	// compare
	for i := 0; i < K; i++ {
		if string(dec[i]) != string(src[i]) {
			t.Fatalf("mismatch at %d", i)
		}
	}
}
