package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go/fec"
)

func main() {
	var (
		tablePath  = flag.String("table", "doc/polar_table_5.3.1.2-1.txt", "3GPP URS table path (index value)")
		N          = flag.Int("N", 32, "block length (power of two)")
		K          = flag.Int("K", 26, "information packets")
		L          = flag.Int("L", 1500, "packet bytes")
		runs       = flag.Int("runs", 10000, "number of Monte Carlo runs")
		loss       = flag.Float64("loss", 0.03, "erasure probability per packet")
		out        = flag.String("out", "docs/reports/fec_eval_3gpp.md", "output markdown path")
		seed       = flag.Int64("seed", 42, "random seed")
		printOrder = flag.Bool("print-order", false, "print 3GPP reliability order for indices < N and exit")
	)
	flag.Parse()

	_ = filepath.Base(*out)

	// Resolve 3GPP table path (support doc/ and docs/ gracefully)
	resolved := resolveTablePath(*tablePath)

	if *printOrder {
		order, err := fec.Load3GPPTable(resolved)
		if err != nil {
			fmt.Printf("failed to load 3GPP table (path=%s): %v\n", resolved, err)
			return
		}
		sel := make([]int, 0, *N)
		for _, idx := range order {
			if idx >= 0 && idx < *N {
				sel = append(sel, idx)
				if len(sel) == *N {
					break
				}
			}
		}
		fmt.Printf("3GPP order for N=%d: %v\n", *N, sel)
		return
	}

	// Build Polar params from 3GPP table
	p, err := fec.NewPacketPolarParamsFrom3GPP(resolved, *N, *K, *L)
	if err != nil {
		fmt.Printf("failed to build polar params from 3GPP (path=%s): %v\n", resolved, err)
		return
	}

	// Reuse existing evaluator by running one-scheme, one-config variant.
	// We'll simulate in-process to produce quick feedback.
	r := runOnePolarEval(p, *N, *K, *L, *runs, *loss, *seed)
	// Write minimal markdown
	_ = writeSimple3GPPReport(*out, resolved, *N, *K, *L, *runs, *loss, r)
}

// resolveTablePath tries the provided path, then common alternatives (doc/ vs docs/), and finally basename in those dirs.
func resolveTablePath(p string) string {
	if fileExists(p) {
		return p
	}
	// Swap doc <-> docs if present
	if strings.Contains(p, "/doc/") {
		alt := strings.Replace(p, "/doc/", "/docs/", 1)
		if fileExists(alt) {
			return alt
		}
	} else if strings.Contains(p, "/docs/") {
		alt := strings.Replace(p, "/docs/", "/doc/", 1)
		if fileExists(alt) {
			return alt
		}
	}
	base := filepath.Base(p)
	for _, dir := range []string{"doc", "docs"} {
		alt := filepath.Join(dir, base)
		if fileExists(alt) {
			return alt
		}
	}
	return p // let the loader error clearly if truly missing
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// Minimal inline helpers to avoid large dependencies on the other CLI
// runOnePolarEval performs Monte Carlo with 3GPP-based polar params.
func runOnePolarEval(p *fec.PacketPolarParams, N, K, L, runs int, loss float64, seed int64) (r struct {
	succ     int
	enc, dec time.Duration
}) {
	rng := newRand(seed)
	for t := 0; t < runs; t++ {
		// build K sources
		src := make([][]byte, K)
		for i := 0; i < K; i++ {
			src[i] = randBytes(rng, L)
		}
		t0 := time.Now()
		par := fec.PacketPolarEncode(p, src)
		r.enc += time.Since(t0)
		// drop
		recv := make([]fec.Packet, 0, N)
		for i := 0; i < N; i++ {
			if rng.Float64() < loss {
				continue
			}
			if i < K {
				recv = append(recv, fec.Packet{Index: i, Data: src[i]})
			} else {
				recv = append(recv, fec.Packet{Index: i, Data: par[i-K]})
			}
		}
		t1 := time.Now()
		_, _, ok := fec.PacketPolarDecodeSplit(p, recv)
		r.dec += time.Since(t1)
		if ok {
			r.succ++
		}
	}
	return r
}

// Small utilities
type fastRand struct{ x uint64 }

func newRand(seed int64) *fastRand   { return &fastRand{x: uint64(seed) | 1} }
func (r *fastRand) next() uint64     { r.x ^= r.x << 7; r.x ^= r.x >> 9; r.x ^= r.x << 8; return r.x }
func (r *fastRand) Float64() float64 { return float64(r.next()>>11) / (1 << 53) }
func randBytes(r *fastRand, n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(r.next())
	}
	return b
}

func writeSimple3GPPReport(path, table string, N, K, L, runs int, loss float64, r struct {
	succ     int
	enc, dec time.Duration
}) error {
	s := fmt.Sprintf(`# Packet-Level Polar (3GPP URS) — Single-Point Evaluation

Table: %s
Params: N=%d K=%d L=%d loss=%.3f runs=%d

Success Rate: %.2f%%
Encode Time (total): %v (avg/run=%.6f ms)
Decode Time (total): %v (avg/run=%.6f ms)
`, table, N, K, L, loss, runs, 100.0*float64(r.succ)/float64(runs), r.enc, float64(r.enc.Milliseconds())/float64(runs), r.dec, float64(r.dec.Milliseconds())/float64(runs))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(s), 0o644)
}
