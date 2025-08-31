package fec_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/fec"
)

// repoRoot finds the repository root by searching for go.mod upwards.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		nd := filepath.Dir(dir)
		if nd == dir || nd == "/" {
			break
		}
		dir = nd
	}
	// fallback to working directory
	return wd
}

func TestPacketLevel_Compare_RS_RLC(t *testing.T) {
	root := repoRoot(t)
	srcPath := filepath.Join(root, "test_data", "train_FD001.txt")
	dstRS := filepath.Join(root, "test_data", "decode_packet_rs.txt")
	dstRLC := filepath.Join(root, "test_data", "decode_packet_rlc.txt")

	// --- Editable parameters ---
	K := 24
	R := 8
	L := 1500
	drops := 2 // per block
	// ---------------------------

	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	rng := rand.New(rand.NewSource(42))

	// RS
	rsEnc, rsDec := time.Duration(0), time.Duration(0)
	outRS := make([]byte, 0, len(src))
	for off := 0; off < len(src); {
		// build K packets
		srcPkts := make([][]byte, K)
		got := 0
		for i := 0; i < K; i++ {
			b := make([]byte, L)
			if off < len(src) {
				n := len(src) - off
				if n > L {
					n = L
				}
				copy(b, src[off:off+n])
				off += n
				got += n
			}
			srcPkts[i] = b
		}
		t0 := time.Now()
		par, err := fec.EncodeRS(srcPkts, K, R)
		if err != nil {
			t.Fatalf("rs enc: %v", err)
		}
		rsEnc += time.Since(t0)
		// drop
		m := K + R
		recv := make([]fec.Packet, 0, m-drops)
		drop := map[int]struct{}{}
		perm := rng.Perm(m)
		for i := 0; i < drops && i < len(perm); i++ {
			drop[perm[i]] = struct{}{}
		}
		for i := 0; i < m; i++ {
			if _, bad := drop[i]; bad {
				continue
			}
			if i < K {
				recv = append(recv, fec.Packet{Index: i, Data: srcPkts[i]})
			} else {
				recv = append(recv, par[i-K])
			}
		}
		t1 := time.Now()
		dec, ok := fec.DecodeRS(recv, K, R)
		if !ok {
			t.Fatalf("rs dec fail")
		}
		rsDec += time.Since(t1)
		// append
		buf := make([]byte, 0, K*L)
		for i := 0; i < K; i++ {
			buf = append(buf, dec[i]...)
		}
		if got > len(buf) {
			got = len(buf)
		}
		outRS = append(outRS, buf[:got]...)
	}
	if len(outRS) > len(src) {
		outRS = outRS[:len(src)]
	}
	if err := os.WriteFile(dstRS, outRS, 0o644); err != nil {
		t.Fatalf("write rs: %v", err)
	}
	if !bytes.Equal(src, outRS) {
		t.Fatalf("RS mismatch")
	}

	// RLC (GF256)
	off := 0
	rlcEnc, rlcDec := time.Duration(0), time.Duration(0)
	outRLC := make([]byte, 0, len(src))
	for off < len(src) {
		srcPkts := make([][]byte, K)
		got := 0
		for i := 0; i < K; i++ {
			b := make([]byte, L)
			if off < len(src) {
				n := len(src) - off
				if n > L {
					n = L
				}
				copy(b, src[off:off+n])
				off += n
				got += n
			}
			srcPkts[i] = b
		}
		t0 := time.Now()
		par := fec.EncodeRLC(srcPkts, K, R, "gf256")
		rlcEnc += time.Since(t0)
		// drop
		m := K + R
		recv := make([]fec.Packet, 0, m-drops)
		drop := map[int]struct{}{}
		perm := rng.Perm(m)
		for i := 0; i < drops && i < len(perm); i++ {
			drop[perm[i]] = struct{}{}
		}
		for i := 0; i < m; i++ {
			if _, bad := drop[i]; bad {
				continue
			}
			if i < K {
				recv = append(recv, fec.Packet{Index: i, Data: srcPkts[i]})
			} else {
				recv = append(recv, par[i-K])
			}
		}
		t1 := time.Now()
		dec, ok := fec.DecodeRLC(recv, K, "gf256")
		if !ok {
			t.Fatalf("rlc dec fail")
		}
		rlcDec += time.Since(t1)
		buf := make([]byte, 0, K*L)
		for i := 0; i < K; i++ {
			buf = append(buf, dec[i]...)
		}
		if got > len(buf) {
			got = len(buf)
		}
		outRLC = append(outRLC, buf[:got]...)
	}
	if len(outRLC) > len(src) {
		outRLC = outRLC[:len(src)]
	}
	if err := os.WriteFile(dstRLC, outRLC, 0o644); err != nil {
		t.Fatalf("write rlc: %v", err)
	}
	if !bytes.Equal(src, outRLC) {
		t.Fatalf("RLC mismatch")
	}

	fmt.Printf("RS: enc(total)=%v dec(total)=%v | RLC: enc(total)=%v dec(total)=%v\n", rsEnc, rsDec, rlcEnc, rlcDec)
}
