package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	mrand "math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go/fec"
)

type scheme string

const (
	schemePolar     scheme = "polar"
	schemePolar3GPP scheme = "polar3gpp"
	schemeRLC       scheme = "rlc"
	schemeRS        scheme = "rs"
)

type config struct {
	N int
	K int
}

type resultKey struct {
	Scheme scheme
	N      int
	K      int
	Loss   float64
}

type agg struct {
	Runs      int
	Successes int
	EncTotal  time.Duration
	DecTotal  time.Duration
	// Accumulated cycle count for rough energy estimate
	Cycles float64
}

type allResults map[resultKey]*agg

type jsonRecord struct {
	Scheme    string  `json:"scheme"`
	N         int     `json:"N"`
	K         int     `json:"K"`
	Loss      float64 `json:"loss"`
	Runs      int     `json:"runs"`
	Successes int     `json:"successes"`
	EncMS     int64   `json:"enc_ms_total"`
	DecMS     int64   `json:"dec_ms_total"`
	Energy    float64 `json:"energy"`
}

func parseConfigs(s string) ([]config, error) {
	parts := strings.Split(s, ";")
	out := make([]config, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var a, b int
		if _, err := fmt.Sscanf(p, "%d,%d", &a, &b); err != nil {
			return nil, fmt.Errorf("bad config %q: %w", p, err)
		}
		out = append(out, config{N: a, K: b})
	}
	return out, nil
}

func parseLosses(s string) ([]float64, error) {
	parts := strings.Split(s, ",")
	out := make([]float64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var f float64
		if _, err := fmt.Sscanf(p, "%f", &f); err != nil {
			return nil, fmt.Errorf("bad loss %q: %w", p, err)
		}
		out = append(out, f)
	}
	return out, nil
}

func ensureDir(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return nil
}

func main() {
	var (
		runs           = flag.Int("runs", 100000, "runs per (scheme,config,loss)")
		pktSize        = flag.Int("packet-size", 1500, "bytes per packet")
		cfgStr         = flag.String("configs", "8,7;8,6;16,12;16,11;32,26", "semicolon-separated list of N,K pairs")
		lossStr        = flag.String("loss", "0.005,0.01,0.03,0.05", "comma-separated list of loss probabilities")
		artifacts      = flag.String("artifacts", "tables", "base dir of polar artifacts (per N,K,e)")
		outPath        = flag.String("out", "docs/reports/fec_eval_report.md", "output markdown report path")
		seed           = flag.Int64("seed", 42, "random seed")
		which          = flag.String("scheme", "all", "which scheme to run: polar|polar3gpp|rlc|rs|all")
		cpuPowerW      = flag.Float64("cpu-power-w", 0.5, "active CPU power in watts (for Joule estimate)")
		cpuFreqGHz     = flag.Float64("cpu-freq-ghz", 1.0, "CPU frequency in GHz (for Joule estimate)")
		xorCycles      = flag.Float64("xor-cycles", 1, "cycles per byte XOR")
		mulCycles      = flag.Float64("mul-cycles", 5, "cycles per GF(256) multiply")
		polar3gppTable = flag.String("polar-3gpp-table", "doc/polar_table_5_3_1_2_1_inverted.txt", "3GPP table path (index, rank; larger=more reliable)")
	)
	flag.Parse()

	cfgs, err := parseConfigs(*cfgStr)
	if err != nil {
		fatalf("%v", err)
	}
	losses, err := parseLosses(*lossStr)
	if err != nil {
		fatalf("%v", err)
	}

	rng := mrand.New(mrand.NewSource(*seed))
	results := make(allResults)

	runPolar := *which == "all" || *which == string(schemePolar)
	runPolar3 := *which == "all" || *which == string(schemePolar3GPP)
	runRLC := *which == "all" || *which == string(schemeRLC)
	runRS := *which == "all" || *which == string(schemeRS)

	freqHz := *cpuFreqGHz * 1e9
	for _, cfg := range cfgs {
		N := cfg.N
		K := cfg.K
		if N <= 0 || K <= 0 || K >= N {
			fatalf("invalid config N=%d K=%d", N, K)
		}
		R := N - K
		if runRS && N > 255 {
			fatalf("RS requires N<=255 (got %d)", N)
		}

		// Precompute Polar encode energy weights if we'll run Polar
		var polarGpar [][]uint64
		var polarWeights []int
		var polar3Gpar [][]uint64
		var polar3Weights []int
		var polar3Params *fec.PacketPolarParams
		// Resolve 3GPP table once per config
		resolved3 := resolveTablePath(*polar3gppTable)
		if runPolar3 {
			pp3, err := fec.NewPacketPolarParamsFrom3GPP(resolved3, N, K, *pktSize)
			if err != nil {
				fatalf("polar3gpp params: %v", err)
			}
			polar3Params = pp3
			polar3Gpar = polar3Params.Gpar
			polar3Weights = make([]int, len(polar3Gpar))
			for j := 0; j < len(polar3Gpar); j++ {
				w := 0
				for _, word := range polar3Gpar[j] {
					x := word
					for x != 0 {
						x &= x - 1
						w++
					}
				}
				polar3Weights[j] = w
			}
		}

		for _, loss := range losses {
			if loss < 0 || loss >= 1 {
				fatalf("invalid loss %.4f", loss)
			}
			e := int(math.Round(loss * float64(N)))
			if e < 1 {
				e = 1
			}
			if e > R {
				e = R
			}

			// Build sources for each run fresh (random). We'll reuse buffers for speed.
			// For fairness, the content doesn't affect decode probability.

			// Prepare Polar params per-loss (due to artifacts keyed by e)
			var polarParams *fec.PacketPolarParams
			if runPolar {
				// Prefer artifacts if present
				dir := filepath.Join(*artifacts, fmt.Sprintf("N%d_K%d_e%d", N, K, e))
				if st, err := os.Stat(dir); err == nil && st.IsDir() {
					pp, err := fec.NewPacketPolarParamsFromArtifacts(*artifacts, N, K, e, *pktSize)
					if err != nil {
						fatalf("load polar artifacts N=%d K=%d e=%d: %v", N, K, e, err)
					}
					polarParams = pp
				} else {
					// Fallback to runtime with BEC epsilon ~ loss
					pp, err := fec.NewPacketPolarParams(N, K, loss, *pktSize)
					if err != nil {
						fatalf("polar params: %v", err)
					}
					polarParams = pp
				}
				if polarGpar == nil {
					polarGpar = polarParams.Gpar
					// weights per parity row
					polarWeights = make([]int, len(polarGpar))
					for j := 0; j < len(polarGpar); j++ {
						w := 0
						for _, word := range polarGpar[j] {
							// popcount word
							x := word
							for x != 0 {
								x &= x - 1
								w++
							}
						}
						polarWeights[j] = w
					}
				}
			}

			for _, sch := range []scheme{schemePolar, schemePolar3GPP, schemeRLC, schemeRS} {
				if (sch == schemePolar && !runPolar) || (sch == schemePolar3GPP && !runPolar3) || (sch == schemeRLC && !runRLC) || (sch == schemeRS && !runRS) {
					continue
				}
				key := resultKey{Scheme: sch, N: N, K: K, Loss: loss}
				results[key] = &agg{}
				a := results[key]
				a.Runs = *runs

				for run := 0; run < *runs; run++ {
					// Build one block of K source packets
					srcPkts := make([][]byte, K)
					for i := 0; i < K; i++ {
						b := make([]byte, *pktSize)
						// Fill with random content
						for j := range b {
							b[j] = byte(rng.Intn(256))
						}
						srcPkts[i] = b
					}

					// Encode according to scheme
					var par []fec.Packet
					var encStart time.Time
					switch sch {
					case schemePolar:
						encStart = time.Now()
						parity := fec.PacketPolarEncode(polarParams, srcPkts)
						a.EncTotal += time.Since(encStart)
						par = make([]fec.Packet, R)
						for j := 0; j < R; j++ {
							par[j] = fec.Packet{Index: K + j, Data: parity[j]}
						}
						// Cycles: XORs = sum(weights)*L * xorCycles
						sumW := 0
						for _, w := range polarWeights {
							sumW += w
						}
						a.Cycles += float64(sumW**pktSize) * (*xorCycles)
					case schemePolar3GPP:
						encStart = time.Now()
						parity := fec.PacketPolarEncode(polar3Params, srcPkts)
						a.EncTotal += time.Since(encStart)
						par = make([]fec.Packet, R)
						for j := 0; j < R; j++ {
							par[j] = fec.Packet{Index: K + j, Data: parity[j]}
						}
						sumW := 0
						for _, w := range polar3Weights {
							sumW += w
						}
						a.Cycles += float64(sumW**pktSize) * (*xorCycles)
					case schemeRLC:
						encStart = time.Now()
						parity := fec.EncodeRLC(srcPkts, K, R, "gf256")
						a.EncTotal += time.Since(encStart)
						par = parity
						// Cycles encode: R*K*(L mul + L xor)
						muls := R * K * *pktSize
						xors := muls
						a.Cycles += float64((*mulCycles)*float64(muls) + (*xorCycles)*float64(xors))
					case schemeRS:
						encStart = time.Now()
						parity, err := fec.EncodeRS(srcPkts, K, R)
						if err != nil {
							fatalf("rs encode: %v", err)
						}
						a.EncTotal += time.Since(encStart)
						par = parity
						// Cycles encode similar to RLC
						muls := R * K * *pktSize
						xors := muls
						a.Cycles += float64((*mulCycles)*float64(muls) + (*xorCycles)*float64(xors))
					}

					// Random drops per packet with probability=loss
					recv := make([]fec.Packet, 0, N)
					for i := 0; i < N; i++ {
						if rng.Float64() < loss {
							continue
						}
						if i < K {
							recv = append(recv, fec.Packet{Index: i, Data: srcPkts[i]})
						} else {
							recv = append(recv, par[i-K])
						}
					}

					// Decode
					decStart := time.Now()
					var ok bool
					switch sch {
					case schemePolar:
						_, met, ok2 := fec.PacketPolarDecodeSplit(polarParams, recv)
						ok = ok2
						a.DecTotal += time.Since(decStart)
						// Cycles decode approx: XOR bytes in replay
						a.Cycles += float64(met.BytesXored) * (*xorCycles)
					case schemePolar3GPP:
						_, met, ok2 := fec.PacketPolarDecodeSplit(polar3Params, recv)
						ok = ok2
						a.DecTotal += time.Since(decStart)
						a.Cycles += float64(met.BytesXored) * (*xorCycles)
					case schemeRLC:
						_, ok2 := fec.DecodeRLC(recv, K, "gf256")
						ok = ok2
						a.DecTotal += time.Since(decStart)
						// Cycles decode approx: r pivots where r=min(K,len(recv))
						r := K
						if len(recv) < r {
							r = len(recv)
						}
						// normalize r rows + eliminate roughly r*(m-1)
						muls := r * *pktSize // L mul per pivot row (payload)
						xors := 0
						m := len(recv)
						if m > 0 {
							muls += r * (m - 1) * *pktSize
							xors += r * (m - 1) * *pktSize
						}
						a.Cycles += float64((*mulCycles)*float64(muls) + (*xorCycles)*float64(xors))
					case schemeRS:
						_, ok2 := fec.DecodeRS(recv, K, R)
						ok = ok2
						a.DecTotal += time.Since(decStart)
						// Similar estimate as RLC
						r := K
						if len(recv) < r {
							r = len(recv)
						}
						muls := r * *pktSize
						xors := 0
						m := len(recv)
						if m > 0 {
							muls += r * (m - 1) * *pktSize
							xors += r * (m - 1) * *pktSize
						}
						a.Cycles += float64((*mulCycles)*float64(muls) + (*xorCycles)*float64(xors))
					}
					if ok {
						a.Successes++
					}
				}
			}
		}
	}

	// Write JSON alongside MD
	if err := ensureDir(*outPath); err != nil {
		fatalf("%v", err)
	}
	ts := time.Now().Format("20060102_150405")
	jsonPath := strings.TrimSuffix(*outPath, ".md") + "_" + ts + ".json"
	mdPath := strings.TrimSuffix(*outPath, ".md") + "_" + ts + ".md"
	jf, err := os.Create(jsonPath)
	if err != nil {
		fatalf("create json: %v", err)
	}
	enc := json.NewEncoder(jf)
	enc.SetIndent("", "  ")
	// flatten results
	recs := make([]jsonRecord, 0, len(results))
	factor := 0.0
	if freqHz > 0 {
		factor = (*cpuPowerW) / freqHz
	}
	for k, v := range results {
		if v == nil {
			continue
		}
		recs = append(recs, jsonRecord{
			Scheme:    string(k.Scheme),
			N:         k.N,
			K:         k.K,
			Loss:      k.Loss,
			Runs:      v.Runs,
			Successes: v.Successes,
			EncMS:     v.EncTotal.Milliseconds(),
			DecMS:     v.DecTotal.Milliseconds(),
			Energy:    factor * v.Cycles,
		})
	}
	if err := enc.Encode(struct {
		Records []jsonRecord `json:"records"`
	}{Records: recs}); err != nil {
		fatalf("write json: %v", err)
	}
	_ = jf.Close()

	// Generate Markdown report
	if err := writeMarkdown(mdPath, results, factor); err != nil {
		fatalf("write md: %v", err)
	}
	fmt.Printf("Report written: %s\nJSON: %s\n", mdPath, jsonPath)
}

func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}

func writeMarkdown(path string, res allResults, factor float64) error {
	if err := ensureDir(path); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Gather unique sets for ordering
	type cfg struct{ N, K int }
	cfgSet := map[cfg]struct{}{}
	lossesSet := map[float64]struct{}{}
	schemesSet := map[scheme]struct{}{}
	for k := range res {
		cfgSet[cfg{N: k.N, K: k.K}] = struct{}{}
		lossesSet[k.Loss] = struct{}{}
		schemesSet[k.Scheme] = struct{}{}
	}
	cfgs := make([]cfg, 0, len(cfgSet))
	for c := range cfgSet {
		cfgs = append(cfgs, c)
	}
	sort.Slice(cfgs, func(i, j int) bool {
		if cfgs[i].N != cfgs[j].N {
			return cfgs[i].N < cfgs[j].N
		}
		return cfgs[i].K < cfgs[j].K
	})
	losses := make([]float64, 0, len(lossesSet))
	for l := range lossesSet {
		losses = append(losses, l)
	}
	sort.Float64s(losses)
	schemes := make([]scheme, 0, len(schemesSet))
	for s := range schemesSet {
		schemes = append(schemes, s)
	}
	sort.Slice(schemes, func(i, j int) bool { return schemes[i] < schemes[j] })

	fmt.Fprintf(f, "# FEC Evaluation Report — Polar vs. RLC vs. RS\n\n")
	fmt.Fprintf(f, "Generated: %s\n\n", time.Now().Format(time.RFC3339))

	// Success Rate tables per (N,K)
	for _, c := range cfgs {
		fmt.Fprintf(f, "## (N=%d, K=%d)\n\n", c.N, c.K)
		// Success rate
		fmt.Fprintf(f, "### Success Rate (%%)\n\n")
		fmt.Fprintf(f, "| Scheme | %s |\n", joinLossHeaders(losses))
		// Build divider without trailing pipe
		div := make([]string, 0, 1+len(losses))
		div = append(div, "---")
		for range losses {
			div = append(div, "---")
		}
		fmt.Fprintf(f, "|%s\n", ""+strings.Join(div, "|"))
		for _, s := range schemes {
			fmt.Fprintf(f, "| %s ", strings.ToUpper(string(s)))
			for _, l := range losses {
				k := resultKey{Scheme: s, N: c.N, K: c.K, Loss: l}
				a := res[k]
				if a == nil || a.Runs == 0 {
					fmt.Fprintf(f, "|  ")
					continue
				}
				sr := 100.0 * float64(a.Successes) / float64(a.Runs)
				fmt.Fprintf(f, "| %.2f ", sr)
			}
			fmt.Fprintf(f, "|\n")
		}
		fmt.Fprintf(f, "\n")

		// Encoding times
		fmt.Fprintf(f, "### Encoding Time (ms)\n\n")
		fmt.Fprintf(f, "| Scheme | Total | Avg/Run |\n")
		fmt.Fprintf(f, "|---|---:|---:|\n")
		for _, s := range schemes {
			// Sum over losses to provide a single view per scheme
			var tot time.Duration
			var runs int
			for _, l := range losses {
				a := res[resultKey{Scheme: s, N: c.N, K: c.K, Loss: l}]
				if a == nil {
					continue
				}
				tot += a.EncTotal
				runs += a.Runs
			}
			if runs == 0 {
				continue
			}
			avg := float64(tot.Milliseconds()) / float64(runs)
			fmt.Fprintf(f, "| %s | %d | %.3f |\n", strings.ToUpper(string(s)), tot.Milliseconds(), avg)
		}
		fmt.Fprintf(f, "\n")

		// Decoding times
		fmt.Fprintf(f, "### Decoding Time (ms)\n\n")
		fmt.Fprintf(f, "| Scheme | Total | Avg/Run |\n")
		fmt.Fprintf(f, "|---|---:|---:|\n")
		for _, s := range schemes {
			var tot time.Duration
			var runs int
			for _, l := range losses {
				a := res[resultKey{Scheme: s, N: c.N, K: c.K, Loss: l}]
				if a == nil {
					continue
				}
				tot += a.DecTotal
				runs += a.Runs
			}
			if runs == 0 {
				continue
			}
			avg := float64(tot.Milliseconds()) / float64(runs)
			fmt.Fprintf(f, "| %s | %d | %.3f |\n", strings.ToUpper(string(s)), tot.Milliseconds(), avg)
		}
		fmt.Fprintf(f, "\n")

		// Energy (relative units), per loss
		fmt.Fprintf(f, "### Energy Estimate (J)\n\n")
		fmt.Fprintf(f, "| Scheme | %s |\n", joinLossHeaders(losses))
		div = div[:0]
		div = append(div, "---")
		for range losses {
			div = append(div, "---")
		}
		fmt.Fprintf(f, "|%s\n", strings.Join(div, "|"))
		for _, s := range schemes {
			fmt.Fprintf(f, "| %s ", strings.ToUpper(string(s)))
			for _, l := range losses {
				a := res[resultKey{Scheme: s, N: c.N, K: c.K, Loss: l}]
				if a == nil {
					fmt.Fprintf(f, "|  ")
					continue
				}
				fmt.Fprintf(f, "| %.6f ", factor*a.Cycles)
			}
			fmt.Fprintf(f, "|\n")
		}
		fmt.Fprintf(f, "\n\n")
	}

	// Notes
	fmt.Fprintf(f, "---\n\n")
	fmt.Fprintf(f, "Notes:\n\n- Loss model: i.i.d. per-packet with probability p.\n- Polar uses precomputed (N,K,e) artifacts when available; else falls back to BEC-epsilon selection with eps≈loss.\n- Energy is a rough proxy: Polar counts XOR-bytes; RS/RLC assume 5 cycles per GF(256) multiply and 1 per XOR.\n")
	return nil
}

func joinLossHeaders(losses []float64) string {
	parts := make([]string, len(losses))
	for i, l := range losses {
		parts[i] = fmt.Sprintf("p=%.3f", l)
	}
	return strings.Join(parts, " | ")
}

// resolveTablePath tries the provided path, then common alternatives (doc/ vs docs/), and finally basename in those dirs.
func resolveTablePath(p string) string {
	if fileExists(p) {
		return p
	}
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
	return p
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
