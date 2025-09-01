package fec_test

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/fec"
)

// helpers
func repoRootRQ(t *testing.T) string {
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
	return wd
}

// TestRaptorQ_ExperimentA validates p=0 correctness with systematic fast path.
// Note: mark as short to avoid running by default in long CI; uncomment to enable heavy runs.
func TestRaptorQ_ExperimentA(t *testing.T) {
	// t.Skip("skip by default; enable when running FEC experiments")

	root := repoRootRQ(t)
	srcPath := filepath.Join(root, "test_data", "train_FD001.txt")
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	const (
		K = 26
		L = 1500
		N = 32
	)

	encSum, decSum := time.Duration(0), time.Duration(0)
	for rep := 0; rep < 200; rep++ {
		// segment into generations of size K*L
		off := 0
		out := make([]byte, 0, len(src))
		for off < len(src) {
			genEnd := off + K*L
			if genEnd > len(src) {
				genEnd = len(src)
			}
			data := make([]byte, genEnd-off)
			copy(data, src[off:genEnd])
			off = genEnd

			t0 := time.Now()
			enc, err := fec.NewRaptorQEncoder(data, K, L)
			if err != nil {
				t.Fatalf("enc: %v", err)
			}
			encSum += time.Since(t0)

			dec, err := fec.NewRaptorQDecoder(len(data), L)
			if err != nil {
				t.Fatalf("dec: %v", err)
			}

			// p=0: deliver exactly K systematic symbols
			for i := uint32(0); i < uint32(K); i++ {
				okTry, err := dec.AddSymbol(i, enc.GenSymbol(i))
				if err != nil {
					t.Fatalf("add: %v", err)
				}
				if !okTry {
					t.Fatalf("unexpected not ready at p=0")
				}
			}
			t1 := time.Now()
			ok, got, err := dec.Decode()
			if err != nil || !ok {
				t.Fatalf("decode: %v ok=%v", err, ok)
			}
			decSum += time.Since(t1)
			out = append(out, got...)
		}
		if !bytes.Equal(out, src) {
			t.Fatalf("mismatch rep %d", rep)
		}
	}
	t.Logf("RaptorQ p=0: enc(total)=%v dec(total)=%v", encSum, decSum)
}

// TestRaptorQ_ExperimentB performs a small-sample bake-off across schemes.
// This is a scaled-down version to keep CI reasonable; adjust counts for full study.
func TestRaptorQ_ExperimentB_Scaled(t *testing.T) {
	// t.Skip("skip by default; enable when running FEC experiments")

	const (
		K = 5
		L = 1100
		N = 8
	)
	// 3 MB object
	obj := make([]byte, 5<<20)
	if _, err := crand.Read(obj); err != nil {
		t.Fatalf("rand: %v", err)
	}
	rng := mrand.New(mrand.NewSource(1337))
	ps := []float64{0.0, 0.001, 0.005, 0.010, 0.05}
	trials := 1 // scale up to 10k for full bake-off

	schemes := []string{"raptorq", "rs", "rlc"}
	for _, scheme := range schemes {
		for _, p := range ps {
			okCnt := 0
			encTotal, decTotal := time.Duration(0), time.Duration(0)
			for rep := 0; rep < trials; rep++ {
				// iterate generations
				off := 0
				out := make([]byte, 0, len(obj))
				for off < len(obj) {
					genEnd := off + K*L
					if genEnd > len(obj) {
						genEnd = len(obj)
					}
					data := obj[off:genEnd]
					off = genEnd

					switch scheme {
					case "raptorq":
						t0 := time.Now()
						enc, err := fec.NewRaptorQEncoder(data, K, L)
						if err != nil {
							t.Fatalf("enc: %v", err)
						}
						encTotal += time.Since(t0)
						dec, err := fec.NewRaptorQDecoder(len(data), L)
						if err != nil {
							t.Fatalf("dec: %v", err)
						}
						// emit N symbols, drop Bernoulli(p)
						for i := 0; i < N; i++ {
							if rng.Float64() < p {
								continue
							}
							id := uint32(i)
							okTry, err := dec.AddSymbol(id, enc.GenSymbol(id))
							if err != nil {
								t.Fatalf("add: %v", err)
							}
							_ = okTry
						}
						t1 := time.Now()
						ok, got, err := dec.Decode()
						decTotal += time.Since(t1)
						if err != nil {
							continue
						}
						if !ok {
							continue
						}
						out = append(out, got...)
					case "rs":
						// build K sources
						src := make([][]byte, K)
						for i := 0; i < K; i++ {
							b := make([]byte, L)
							start := i * L
							if start < len(data) {
								end := start + L
								if end > len(data) {
									end = len(data)
								}
								copy(b, data[start:end])
							}
							src[i] = b
						}
						t0 := time.Now()
						par, err := fec.EncodeRS(src, K, N-K)
						if err != nil {
							t.Fatalf("rs enc: %v", err)
						}
						encTotal += time.Since(t0)
						// loss
						recv := make([]fec.Packet, 0, N)
						for i := 0; i < N; i++ {
							if rng.Float64() < p {
								continue
							}
							if i < K {
								recv = append(recv, fec.Packet{Index: i, Data: src[i]})
							} else {
								recv = append(recv, par[i-K])
							}
						}
						t1 := time.Now()
						dec, ok := fec.DecodeRS(recv, K, N-K)
						decTotal += time.Since(t1)
						if !ok {
							out = nil
							break
						}
						for i := 0; i < K; i++ {
							out = append(out, dec[i]...)
						}
					case "rlc":
						src := make([][]byte, K)
						for i := 0; i < K; i++ {
							b := make([]byte, L)
							start := i * L
							if start < len(data) {
								end := start + L
								if end > len(data) {
									end = len(data)
								}
								copy(b, data[start:end])
							}
							src[i] = b
						}
						t0 := time.Now()
						par := fec.EncodeRLC(src, K, N-K, "gf256")
						encTotal += time.Since(t0)
						recv := make([]fec.Packet, 0, N)
						for i := 0; i < N; i++ {
							if rng.Float64() < p {
								continue
							}
							if i < K {
								recv = append(recv, fec.Packet{Index: i, Data: src[i]})
							} else {
								recv = append(recv, par[i-K])
							}
						}
						t1 := time.Now()
						dec, ok := fec.DecodeRLC(recv, K, "gf256")
						decTotal += time.Since(t1)
						if !ok {
							out = nil
							break
						}
						for i := 0; i < K; i++ {
							out = append(out, dec[i]...)
						}
					case "polar":
						pp, err := fec.NewPacketPolarParams(N, K, 0.05, L)
						if err != nil {
							t.Fatalf("polar params: %v", err)
						}
						src := make([][]byte, K)
						for i := 0; i < K; i++ {
							b := make([]byte, L)
							start := i * L
							if start < len(data) {
								end := start + L
								if end > len(data) {
									end = len(data)
								}
								copy(b, data[start:end])
							}
							src[i] = b
						}
						t0 := time.Now()
						par := fec.PacketPolarEncode(pp, src)
						encTotal += time.Since(t0)
						recv := make([]fec.Packet, 0, N)
						for i := 0; i < N; i++ {
							if rng.Float64() < p {
								continue
							}
							if i < K {
								recv = append(recv, fec.Packet{Index: i, Data: src[i]})
							} else {
								recv = append(recv, fec.Packet{Index: i, Data: par[i-K]})
							}
						}
						t1 := time.Now()
						dec, ok := fec.PacketPolarDecode(pp, recv)
						decTotal += time.Since(t1)
						if !ok {
							out = nil
							break
						}
						for i := 0; i < K; i++ {
							out = append(out, dec[i]...)
						}
					}
				}
				if out == nil {
					continue
				}
				out = out[:len(obj)]
				if bytes.Equal(out, obj) {
					okCnt++
				}
			}
			rate := float64(okCnt) / float64(trials)
			fmt.Printf("scheme=%s p=%.3f ok=%.4f enc(total)=%v dec(total)=%v\n", scheme, p, rate, encTotal, decTotal)
		}
	}
}
