package fec_test

import (
	"crypto/sha256"
	"math/rand"
	"testing"

	"github.com/quic-go/quic-go/fec"
)

// TestRandomInterleaverIdentity ensures ByteRandomInterleave then ByteRandomDeinterleave returns original data.
func TestRandomInterleaverIdentity(t *testing.T) {
	L := 32
	N := 1024
	// Build input group
	in := make([][]byte, L)
	for i := 0; i < L; i++ {
		b := make([]byte, N)
		for j := 0; j < N; j++ {
			b[j] = byte((i*131 + j*17) & 0xff)
		}
		in[i] = b
	}
	// permutation
	perm := rand.New(rand.NewSource(1234)).Perm(N)
	out, err := fec.ByteRandomInterleave(in, perm)
	if err != nil {
		t.Fatalf("interleave: %v", err)
	}
	rec, err := fec.ByteRandomDeinterleave(out, perm)
	if err != nil {
		t.Fatalf("deinterleave: %v", err)
	}
	// compare via hashes
	for i := 0; i < L; i++ {
		h1 := sha256.Sum256(in[i])
		h2 := sha256.Sum256(rec[i])
		if h1 != h2 {
			t.Fatalf("packet %d mismatch after deinterleave", i)
		}
	}
}

// TestSlopeInterleaverIdentity ensures SlopeInterleave then SlopeDeinterleave returns original data.
func TestSlopeInterleaverIdentity(t *testing.T) {
	L := 32
	N := 1024
	in := make([][]byte, L)
	for i := 0; i < L; i++ {
		b := make([]byte, N)
		for j := 0; j < N; j++ {
			b[j] = byte((i*19 + j*7 + 3) & 0xff)
		}
		in[i] = b
	}
	sp, err := fec.NewSlopeParams(N, L, 0, 0) // step=M-1, offset=0
	if err != nil {
		t.Fatalf("slope params: %v", err)
	}
	out, err := fec.SlopeInterleave(in, N, sp)
	if err != nil {
		t.Fatalf("interleave: %v", err)
	}
	rec, err := fec.SlopeDeinterleave(out, N, sp)
	if err != nil {
		t.Fatalf("deinterleave: %v", err)
	}
	for i := 0; i < L; i++ {
		h1 := sha256.Sum256(in[i])
		h2 := sha256.Sum256(rec[i])
		if h1 != h2 {
			t.Fatalf("packet %d mismatch after slope deinterleave", i)
		}
	}
}
