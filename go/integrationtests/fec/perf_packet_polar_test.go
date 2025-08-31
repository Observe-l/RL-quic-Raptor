package fec_test

import (
	"bytes"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/fec"
)

func TestPacketLevelPolar_Perf(t *testing.T) {
	root := repoRoot(t)
	srcPath := filepath.Join(root, "test_data", "train_FD001.txt")
	dstPath := filepath.Join(root, "test_data", "decode_packet_level.txt")
	table := filepath.Join(root, "docs", "polar_table_5_3_1_2_1_inverted.txt")

	// --- Editable parameters ---
	N := 1024       // total packets per block (power of two)
	K := 512        // source packets per block
	L := 512        // bytes per packet
	drops := 100    // packets dropped per block
	epsilon := 0.18 // BEC epsilon for A selection
	e := drops      // preferred artifacts are keyed by e (=drops)
	// ---------------------------

	if N&(N-1) != 0 {
		t.Fatalf("N must be power of two")
	}
	if K <= 0 || K >= N {
		t.Fatalf("invalid K for N")
	}
	R := N - K

	t.Logf("Packet-Polar Params: N=%d, K=%d, R=%d, L=%d, drops=%d, eps=%.3f", N, K, R, L, drops, epsilon)
	fmt.Printf("Packet-Polar Params: N=%d, K=%d, R=%d, L=%d, drops=%d, eps=%.3f\n", N, K, R, L, drops, epsilon)

	// Load file
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}

	// Build params: prefer per-(N,K,e) artifacts under tables/, then fallback to epsilon table, else runtime
	var p *fec.PacketPolarParams
	// try 3pg first
	if _, err := os.Stat(table); err == nil {
		if pp, err := fec.NewPacketPolarParamsFrom3GPP(table, N, K, L); err == nil {
			p = pp
		}
	}

	// try artifacts first
	artBase := filepath.Join(root, "tables")
	if p == nil {
		if _, err := os.Stat(filepath.Join(artBase, fmt.Sprintf("N%d_K%d_e%d", N, K, e))); err == nil {
			if pp, err := fec.NewPacketPolarParamsFromArtifacts(artBase, N, K, e, L); err == nil {
				p = pp
				t.Logf("loaded artifacts from %s", artBase)
			} else {
				t.Logf("warn: artifacts load failed: %v", err)
			}
		}
	}
	if p == nil {
		// try epsilon table
		tablePath := filepath.Join(root, "fec", fmt.Sprintf("packet_polar_table_N%d_K%d.json", N, K))
		if _, err := os.Stat(tablePath); err == nil {
			tbl, err := fec.LoadPacketPolarTable(tablePath)
			if err != nil {
				t.Fatalf("load offline table: %v", err)
			}
			pp, err := fec.NewPacketPolarParamsFromTable(tbl, epsilon, L)
			if err != nil {
				t.Fatalf("params from table: %v", err)
			}
			p = pp
		}
	}
	if p == nil {
		// fallback to runtime construction
		pp, err := fec.NewPacketPolarParams(N, K, epsilon, L)
		if err != nil {
			t.Fatalf("params: %v", err)
		}
		p = pp
	}

	encTotal := time.Duration(0)
	decTotal := time.Duration(0)
	blocks := 0

	out := make([]byte, 0, len(src))
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	// rng := mrand.New(mrand.NewSource(956)) // fixed seed for repeatability

	// Process the file in blocks of K*L bytes
	for off := 0; off < len(src); {
		// Prepare K source packets
		srcPkts := make([][]byte, K)
		blockBytes := 0
		for i := 0; i < K; i++ {
			pkt := make([]byte, L)
			if off < len(src) {
				n := len(src) - off
				if n > L {
					n = L
				}
				copy(pkt, src[off:off+n])
				off += n
				blockBytes += n
			}
			srcPkts[i] = pkt
		}

		// Encode parity
		tEnc := time.Now()
		parPkts := fec.PacketPolarEncode(p, srcPkts)
		encTotal += time.Since(tEnc)

		// Build received set with drops
		idx := rng.Perm(N)
		recv := make([]fec.Packet, 0, N-drops)
		// mark dropped indices
		dropped := make(map[int]struct{}, drops)
		for i := 0; i < drops && i < len(idx); i++ {
			dropped[idx[i]] = struct{}{}
		}
		for i := 0; i < N; i++ {
			if _, bad := dropped[i]; bad {
				continue
			}
			if i < K {
				recv = append(recv, fec.Packet{Index: i, Data: srcPkts[i]})
			} else {
				j := i - K
				recv = append(recv, fec.Packet{Index: i, Data: parPkts[j]})
			}
		}

		// Decode
		tDec := time.Now()
		decSrc, met, ok := fec.PacketPolarDecodeSplit(p, recv)
		d := time.Since(tDec)
		if !ok {
			t.Fatalf("decode failed at block %d (drops=%d)", blocks, drops)
		}
		decTotal += d
		blocks++
		// print split metrics per block occasionally (optional)
		if blocks == 1 {
			fmt.Printf("Split metrics (block %d): elim=%v apply=%v rank=%d swaps=%d xors=%d bytesXor=%d\n", blocks, met.ElimTime, met.ApplyTime, met.Rank, met.RowSwaps, met.RowXors, met.BytesXored)
		}

		// Append only the original bytes in this block (blockBytes)
		// concatenate K decoded packets and slice to blockBytes
		buf := make([]byte, 0, K*L)
		for i := 0; i < K; i++ {
			buf = append(buf, decSrc[i]...)
		}
		if blockBytes > len(buf) {
			blockBytes = len(buf)
		}
		out = append(out, buf[:blockBytes]...)
	}

	if len(out) > len(src) {
		out = out[:len(src)]
	}
	if err := os.WriteFile(dstPath, out, 0o644); err != nil {
		t.Fatalf("write decoded: %v", err)
	}
	if !bytes.Equal(src, out) {
		t.Fatalf("decoded output mismatches input")
	}

	total := encTotal + decTotal
	t.Logf("Packet-Polar encode time (total): %v", encTotal)
	t.Logf("Packet-Polar decode time (total) [drops/block=%d]: %v", drops, decTotal)
	t.Logf("Packet-Polar blocks: %d; total time: %v", blocks, total)
	fmt.Printf("Packet-Polar encode(total)=%v, decode(total)=%v, blocks=%d, total=%v\n", encTotal, decTotal, blocks, total)
}
