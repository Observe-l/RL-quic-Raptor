package fec_test

import (
	"bytes"
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/quic-go/quic-go/fec"
)

// TestBytePolar_NoLoss validates end-to-end encode->interleave->deinterleave->decode at p=0 for both interleavers.
func TestBytePolar_NoLoss(t *testing.T) {
	root := repoRoot(t)
	idxPath := filepath.Join(root, "fec", "encoding_index.bin")
	encodingIndex, err := fec.LoadEncodingIndex(idxPath)
	if err != nil {
		t.Fatalf("load encoding index: %v", err)
	}
	// small data to keep runtime quick
	data := make([]byte, 64*1024) // 64 KiB
	for i := range data {
		data[i] = byte((i*131 + 7) & 0xff)
	}
	Kbytes := 512
	// split into Kbytes messages
	var msgs [][]byte
	for off := 0; off < len(data); off += Kbytes {
		end := off + Kbytes
		if end > len(data) {
			end = len(data)
		}
		b := make([]byte, Kbytes)
		copy(b, data[off:end])
		msgs = append(msgs, b)
	}
	// encode each packet to 1024 bytes
	enc := make([][]byte, len(msgs))
	for i := range msgs {
		cw, err := fec.BytePolarEncodePacket(msgs[i], encodingIndex, Kbytes)
		if err != nil {
			t.Fatalf("encode pkt %d: %v", i, err)
		}
		enc[i] = cw
	}
	// Test both interleavers for L in {8,32}
	inters := []string{"random", "slope"}
	Ls := []int{8, 32}
	for _, inter := range inters {
		for _, L := range Ls {
			// group and interleave
			var groups [][][]byte
			var perms [][]int
			for i := 0; i < len(enc); i += L {
				end := i + L
				if end > len(enc) {
					end = len(enc)
				}
				grp := make([][]byte, L)
				copy(grp, enc[i:end])
				for j := end - i; j < L; j++ {
					grp[j] = make([]byte, 1024)
				}
				if inter == "random" {
					perm := rand.New(rand.NewSource(42)).Perm(1024)
					out, err := fec.ByteRandomInterleave(grp, perm)
					if err != nil {
						t.Fatalf("random interleave: %v", err)
					}
					groups = append(groups, out)
					perms = append(perms, perm)
				} else {
					sp, err := fec.NewSlopeParams(1024, L, 0, 0)
					if err != nil {
						t.Fatalf("slope params: %v", err)
					}
					out, err := fec.SlopeInterleave(grp, 1024, sp)
					if err != nil {
						t.Fatalf("slope interleave: %v", err)
					}
					groups = append(groups, out)
					perms = append(perms, nil)
				}
			}
			// deinterleave known and decode
			var dec []byte
			gi := 0
			for _, grp := range groups {
				var de [][]byte
				var masks [][]bool
				if inter == "random" {
					var err error
					de, masks, err = fec.ByteRandomDeinterleaveKnown(grp, perms[gi])
					if err != nil {
						t.Fatalf("random deinterleaveKnown: %v", err)
					}
				} else {
					sp, _ := fec.NewSlopeParams(1024, L, 0, 0)
					var err error
					de, masks, err = fec.SlopeDeinterleaveKnown(grp, 1024, sp)
					if err != nil {
						t.Fatalf("slope deinterleaveKnown: %v", err)
					}
				}
				for s := 0; s < L && len(dec) < len(data); s++ {
					b, ok, err := fec.BytePolarDecodePacket(de[s], masks[s], encodingIndex, Kbytes)
					if err != nil {
						t.Fatalf("decode: %v", err)
					}
					if !ok {
						t.Fatalf("decode failed at s=%d L=%d inter=%s", s, L, inter)
					}
					dec = append(dec, b...)
				}
				gi++
			}
			if len(dec) > len(data) {
				dec = dec[:len(data)]
			}
			if !bytes.Equal(data, dec) {
				t.Fatalf("mismatch for inter=%s L=%d", inter, L)
			}
		}
	}
}
