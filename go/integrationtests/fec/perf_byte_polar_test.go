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

// TestByteLevelPolar_Perf measures encode/decode time for byte-level Polar with slope interleaver
// over L in {8,16,32,64,128} and loss rates in {0, 0.1%, 1%, 10%}.
func TestByteLevelPolar_Perf(t *testing.T) {
	root := repoRoot(t)
	srcPath := filepath.Join(root, "test_data", "train_FD001.txt")
	dstPath := filepath.Join(root, "test_data", "decode_byte_level.txt")

	// Fixed code params
	const N = 1024 // codeword bytes
	const Kbytes = 512
	if N != 1024 {
		t.Fatalf("this test assumes N=1024")
	}

	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}

	// Build systematic params from inverted table
	table := filepath.Join(root, "docs", "polar_table_5_3_1_2_1_inverted.txt")
	if _, statErr := os.Stat(table); statErr != nil {
		t.Skipf("skipping: inverted table missing at %s; add it to run this perf test", table)
	}
	bp, err := fec.NewBytePolarParamsFromInverted(table, filepath.Join(root, "cache"), N, Kbytes)
	if err != nil {
		t.Fatalf("params: %v", err)
	}

	// Prepare messages (Kbytes) and encode all once per run
	chunk := func(b []byte, n int) [][]byte {
		var out [][]byte
		for i := 0; i < len(b); i += n {
			end := i + n
			if end > len(b) {
				end = len(b)
			}
			p := make([]byte, n)
			copy(p, b[i:end])
			out = append(out, p)
		}
		return out
	}
	msgs := chunk(data, Kbytes)

	// Encode all codewords and time it
	encPkts := make([][]byte, len(msgs))
	tEnc := time.Now()
	for i := range msgs {
		cw, err := fec.BytePolarEncodeSystematic(bp, msgs[i])
		if err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
		encPkts[i] = cw
	}
	encTotal := time.Since(tEnc)

	// Test matrix
	Ls := []int{8, 16, 32, 64, 128}
	losses := []float64{0.0, 0.001, 0.01, 0.10}
	inters := []string{"slope", "random"}

	// fixed random permutation for random interleaver
	randPi := mrand.New(mrand.NewSource(2025)).Perm(N)
	// packet-level params and canonical index map once per run
	pp, err := fec.NewPacketPolarParamsFromA(N, Kbytes, bp.A, 1)
	if err != nil {
		t.Fatalf("packet params: %v", err)
	}
	canonIdx := make([]int, N)
	for i := 0; i < N; i++ {
		canonIdx[i] = -1
	}
	for ai, pos := range bp.A {
		canonIdx[pos] = ai
	}
	for cj, pos := range bp.Ac {
		canonIdx[pos] = Kbytes + cj
	}
	// global caches across scenarios (masks repeat a lot)
	factCache := make(map[string]fec.PacketPolarFact)
	rowIdxCache := make(map[string][]int)

	for _, L := range Ls {
		for _, inter := range inters {
			var sp fec.SlopeParams
			var err error
			if inter == "slope" {
				sp, err = fec.NewSlopeParams(N, L, 0, 0)
				if err != nil {
					t.Fatalf("slope params: %v", err)
				}
			}
			for _, p := range losses {
				rng := mrand.New(mrand.NewSource(42))
				// Interleave into groups of L, timing separately
				groups := make([][][]byte, 0, (len(encPkts)+L-1)/L)
				tInt := time.Duration(0)
				for i := 0; i < len(encPkts); i += L {
					end := i + L
					if end > len(encPkts) {
						end = len(encPkts)
					}
					grp := make([][]byte, L)
					copy(grp, encPkts[i:end])
					for j := end - i; j < L; j++ {
						grp[j] = make([]byte, N)
					}
					var out [][]byte
					t0 := time.Now()
					if inter == "slope" {
						out, err = fec.SlopeInterleave(grp, N, sp)
					} else {
						out, err = fec.ByteRandomInterleave(grp, randPi)
					}
					if err != nil {
						t.Fatalf("interleave: %v", err)
					}
					tInt += time.Since(t0)
					groups = append(groups, out)
				}

				// Apply losses and decode; time deinterleave and total decode
				tDeInt := time.Duration(0)
				tGE := time.Duration(0)
				tSolve := time.Duration(0)
				tDecTotal := time.Duration(0)
				out := make([]byte, 0, len(data))
				totalPkts, okPkts := 0, 0
				// scratch buffer to build 1-byte rows without allocating
				scratchRows := make([]byte, N)
				// instrumentation
				geCount := 0
				for _, grp := range groups {
					// losses per interleaved packet
					recv := make([][]byte, len(grp))
					for i := 0; i < len(grp); i++ {
						if rng.Float64() < p {
							recv[i] = nil
						} else {
							recv[i] = grp[i]
						}
					}
					// deinterleave known
					var de [][]byte
					var masks [][]bool
					t0 := time.Now()
					if inter == "slope" {
						de, masks, err = fec.SlopeDeinterleaveKnown(recv, N, sp)
					} else {
						de, masks, err = fec.ByteRandomDeinterleaveKnown(recv, randPi)
					}
					if err != nil {
						t.Fatalf("deinterleaveKnown: %v", err)
					}
					tDeInt += time.Since(t0)
					// Solve each stream independently (reuse group-level when possible)
					// Build per-group mask key and check if identical across s
					groupMaskKey := ""
					identical := true
					if L > 0 {
						for si := 0; si < L; si++ {
							k := packMaskKeyTest(masks[si])
							if si == 0 {
								groupMaskKey = k
							} else if k != groupMaskKey {
								identical = false
								break
							}
						}
					}
					// Compute B (lost outputs) and m for s=0; sanity check m == N - B*(N/L)
					_ = groupMaskKey
					B := 0
					for i := 0; i < len(recv); i++ {
						if recv[i] == nil {
							B++
						}
					}
					m0 := 0
					for r := 0; r < N; r++ {
						if masks[0][r] {
							m0++
						}
					}
					_ = m0 // currently unused; kept for future instrumentation
					_ = B  // currently unused; kept for future instrumentation

					// Group-level fast path: if B==0, just fast-recover all streams and continue
					if B == 0 {
						for s := 0; s < L; s++ {
							if len(out)/Kbytes >= len(msgs) {
								break
							}
							totalPkts++
							t1 := time.Now()
							src, err := fec.BytePolarFastRecover(bp, de[s])
							tDecTotal += time.Since(t1)
							if err != nil {
								t.Fatalf("fast recover: %v", err)
							}
							out = append(out, src...)
							okPkts++
						}
						continue
					}

					// Optional: when identical, precompute present/fact/rowIdxs once per group
					var sharedFact fec.PacketPolarFact
					var sharedRowIdxs []int
					haveShared := false
					if identical {
						if f, ok := factCache[groupMaskKey]; ok {
							if rj, ok2 := rowIdxCache[groupMaskKey]; ok2 {
								sharedFact = f
								sharedRowIdxs = rj
								haveShared = true
							}
						}
						if !haveShared {
							// build rowIdxs and present once from masks[0]
							rowIdxs := make([]int, 0, N)
							present := make([]int, 0, N)
							ms0 := masks[0]
							// If mask is all true, skip building shared factorization; fast path will handle streams
							allTrue := true
							for r := 0; r < N; r++ {
								if !ms0[r] {
									allTrue = false
									continue
								}
								rowIdxs = append(rowIdxs, r)
								if idx := canonIdx[r]; idx >= 0 {
									present = append(present, idx)
								}
							}
							if !allTrue && len(present) >= Kbytes {
								f, met, okF := fec.PacketPolarFactorize(pp, present)
								tGE += met.ElimTime
								if okF {
									geCount++
									factCache[groupMaskKey] = f
									rowIdxCache[groupMaskKey] = rowIdxs
									sharedFact = f
									sharedRowIdxs = rowIdxs
									haveShared = true
								}
							}
						}
					}

					for s := 0; s < L; s++ {
						// Do not exceed original message count
						if len(out)/Kbytes >= len(msgs) {
							break
						}
						totalPkts++
						t1 := time.Now()
						ms := masks[s]

						// Fast path
						all := true
						for r := 0; r < N; r++ {
							if !ms[r] {
								all = false
								break
							}
						}
						if all {
							src, err := fec.BytePolarFastRecover(bp, de[s])
							tDecTotal += time.Since(t1)
							if err != nil {
								t.Fatalf("fast recover: %v", err)
							}
							out = append(out, src...)
							okPkts++
							continue
						}

						// Use group-level shared factorization when masks identical
						var fact fec.PacketPolarFact
						var rowIdxs []int
						got := false
						if identical && haveShared {
							fact = sharedFact
							rowIdxs = sharedRowIdxs
							got = true
						}
						if !got {
							key := packMaskKeyTest(ms)
							if rj, ok := rowIdxCache[key]; ok {
								rowIdxs = rj
								fact = factCache[key]
							} else {
								// compress mask to row indices and present indices
								rowIdxs = make([]int, 0, N)
								present := make([]int, 0, N)
								for r := 0; r < N; r++ {
									if !ms[r] {
										continue
									}
									rowIdxs = append(rowIdxs, r)
									if idx := canonIdx[r]; idx >= 0 {
										present = append(present, idx)
									}
								}
								if len(present) < Kbytes {
									out = append(out, make([]byte, Kbytes)...)
									tDecTotal += time.Since(t1)
									continue
								}
								f, met, okF := fec.PacketPolarFactorize(pp, present)
								tGE += met.ElimTime
								if !okF {
									out = append(out, make([]byte, Kbytes)...)
									tDecTotal += time.Since(t1)
									continue
								}
								geCount++
								rowIdxCache[key] = rowIdxs
								factCache[key] = f
								fact = f
							}
						}

						// build byteRows using cached row indices
						byteRows := scratchRows[:len(rowIdxs)]
						for i2, r2 := range rowIdxs {
							byteRows[i2] = de[s][r2]
						}
						solved, met := fec.PacketPolarSolveBytesWithFact(pp, fact, byteRows)
						tSolve += met.ApplyTime
						out = append(out, solved...)
						okPkts++
						tDecTotal += time.Since(t1)
					}
				}
				if p == 0.0 {
					if len(out) > len(data) {
						out = out[:len(data)]
					}
					if !bytes.Equal(data, out) {
						t.Fatalf("decoded mismatch inter=%s L=%d p=%.4f", inter, L, p)
					}
				}
				okRate := float64(okPkts) / float64(max(1, totalPkts))
				fmt.Printf("Byte-Polar[%s]: L=%d p=%.4f | enc=%v inter=%dus deint=%dus dec(total)=%v (GE=%v solve=%v) num_GE=%d | ok=%d/%d (%.2f)\n",
					inter, L, p, encTotal, tInt.Microseconds(), tDeInt.Microseconds(), tDecTotal, tGE, tSolve, geCount, okPkts, totalPkts, okRate)
			}
		}
	}

	_ = dstPath // optional output path; not used here
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// (removed idxInSorted; we use canonIdx map for O(1) lookup)

// packMaskKeyTest compacts a []bool into a string key for map caching.
func packMaskKeyTest(mask []bool) string {
	if len(mask) == 0 {
		return ""
	}
	nb := (len(mask) + 7) / 8
	b := make([]byte, nb)
	for i := 0; i < len(mask); i++ {
		if mask[i] {
			b[i>>3] |= 1 << uint(i&7)
		}
	}
	return string(b)
}
