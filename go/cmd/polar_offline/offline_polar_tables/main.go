package main

import (
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go/fec"
)

func main() {
	var NsStr, KsMode, indexing string
	var urs, upo bool
	var W, S float64
	var trials, parallel int
	var seed int64
	var outRoot string
	flag.StringVar(&NsStr, "Ns", "8,16,32,64,128", "comma-separated N values (powers of two)")
	flag.StringVar(&KsMode, "Ks", "all", "K selection: 'all' or 'subset:<N>:<ranges>,<N>:<ranges>' e.g. subset:32:1-31,64:1-63")
	flag.StringVar(&indexing, "indexing", "natural", "indexing convention: natural|bit-reversed (meta only; construction follows natural here)")
	flag.BoolVar(&urs, "urs-baseline", false, "enable URS baseline (meta only)")
	flag.BoolVar(&upo, "upo", false, "enable UPO constraint (meta only)")
	flag.Float64Var(&W, "epsilon-band-width", 0.04, "half width around e/N for epsilon band")
	flag.Float64Var(&S, "epsilon-band-step", 0.005, "epsilon grid step")
	flag.IntVar(&trials, "mc-trials", 100000, "Monte Carlo trials per (N,K,e)")
	flag.IntVar(&parallel, "parallel", 8, "parallel workers")
	flag.Int64Var(&seed, "seed", 0, "RNG seed (0=auto from time.Now)")
	flag.StringVar(&outRoot, "out", "tables", "output root directory")
	flag.Parse()

	Ns := parseIntList(NsStr)
	cfgKs := parseKsMode(KsMode)
	if seed == 0 {
		seed = time.Now().UnixNano()
	}

	// global CSV index
	indexPath := filepath.Join(outRoot, "index.csv")
	if err := os.MkdirAll(outRoot, 0o755); err != nil {
		panic(err)
	}
	fidx, err := os.Create(indexPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", indexPath, err)
		os.Exit(1)
	}
	defer fidx.Close()
	w := csv.NewWriter(fidx)
	_ = w.Write([]string{"N", "K", "e", "eps_center", "A_hash", "parity_order_hash", "table_id", "trials", "success_optimized"})
	w.Flush()

	type job struct{ N, K, e int }
	jobs := make(chan job, 1024)
	lines := make(chan []string, 1024)
	var wg sync.WaitGroup

	// writer goroutine
	var wmu sync.Mutex
	go func() {
		for rec := range lines {
			wmu.Lock()
			_ = w.Write(rec)
			wmu.Unlock()
		}
		w.Flush()
	}()

	// workers
	if parallel < 1 {
		parallel = 1
	}
	for wi := 0; wi < parallel; wi++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for jb := range jobs {
				N := jb.N
				K := jb.K
				e := jb.e
				R := N - K
				epsCenter := float64(e) / float64(N)
				epsGrid := buildEpsGridBand(epsCenter, W, S)

				// Stage A/B: robust A via majority across band
				Asets := make([][]int, len(epsGrid))
				zHash := sha256.New()
				for i, eps := range epsGrid {
					p, err := fec.NewPacketPolarParams(N, K, eps, 1)
					if err != nil {
						fmt.Fprintf(os.Stderr, "[warn] params N=%d K=%d eps=%.6f: %v\n", N, K, eps, err)
						continue
					}
					Asets[i] = append([]int(nil), p.A...)
					b, _ := json.Marshal(p.A)
					zHash.Write(b)
				}
				Arob := majorityA(Asets, N, K)
				Ahash := sha256HexOfJSON(Arob)

				// Build Gpar from Arob (natural indexing)
				G := fecPolarGeneratorBool(log2(N))
				Ac := complement(Arob, N)
				GAA := extract(G, Arob, Arob)
				GAAc := extract(G, Arob, Ac)
				invGAA, ok := invertBoolMatrixGF2Local(GAA)
				if !ok {
					// Fallback: try center epsilon directly
					centerP, err := fec.NewPacketPolarParams(N, K, epsCenter, 1)
					if err == nil {
						Arob = append([]int(nil), centerP.A...)
						Ahash = sha256HexOfJSON(Arob)
						Ac = complement(Arob, N)
						GAA = extract(G, Arob, Arob)
						GAAc = extract(G, Arob, Ac)
						if inv, ok2 := invertBoolMatrixGF2Local(GAA); ok2 {
							invGAA = inv
						} else {
							fmt.Fprintf(os.Stderr, "[warn] G_AA still singular at center (N=%d K=%d e=%d); skipping job.\n", N, K, e)
							continue
						}
					} else {
						fmt.Fprintf(os.Stderr, "[warn] G_AA not invertible and center params failed (N=%d K=%d e=%d): %v\n", N, K, e, err)
						continue
					}
				}
				P := matMulGF2(invGAA, GAAc)
				wordsK := (K + 63) / 64
				Gpar := make([][]uint64, R)
				for j := 0; j < R; j++ {
					row := make([]uint64, wordsK)
					for i := 0; i < K; i++ {
						if P[i][j] {
							row[i>>6] |= 1 << uint(i&63)
						}
					}
					Gpar[j] = row
				}

				// Stage C: parity ordering (coverage heuristic around e)
				cfgSeed := seed ^ int64(N*1_000_000+K*10_000+e)
				order := parityOrderCoverageHeuristic(Gpar, K, max(1, e), 2000, cfgSeed)
				orderHash := sha256HexOfJSON(order)

				// Stage D: Monte Carlo success for the specific e (i.i.d.)
				rng := rand.New(rand.NewSource(cfgSeed))
				res := evalSuccessRates(N, K, Gpar, trials, e, rng)

				// Stage E: write artifacts
				tableID := shortTableID(indexing, epsGrid, Ahash, orderHash)
				base := filepath.Join(outRoot, fmt.Sprintf("N%d_K%d_e%d", N, K, e), "table_"+tableID)
				if err := os.MkdirAll(base, 0o755); err != nil {
					fmt.Fprintf(os.Stderr, "[warn] mkdir %s: %v\n", base, err)
					continue
				}
				writeJSON(filepath.Join(base, "A.json"), Arob)
				writeJSON(filepath.Join(base, "parity_order.json"), order)
				meta := map[string]any{
					"version":             "v1",
					"indexing":            indexing,
					"epsilon_grid":        epsGrid,
					"band_center":         epsCenter,
					"band_policy":         "majority-vote+coverage",
					"upo":                 ternary(upo, "enabled", "disabled"),
					"urs_base":            ternary(urs, "on", "off"),
					"optimization_target": "max_E_rank",
					"parity_order_policy": "coverage-marginal-gain",
					"interleaver_depth":   0,
					"seed":                cfgSeed,
					"A_hash":              "sha256:" + Ahash,
					"parity_order_hash":   "sha256:" + orderHash,
					"table_id":            "table_" + tableID,
				}
				writeJSON(filepath.Join(base, "meta.json"), meta)

				// send index line
				lines <- []string{itoa(N), itoa(K), itoa(e), fmt.Sprintf("%.6f", epsCenter), Ahash, orderHash, "table_" + tableID, itoa(trials), fmt.Sprintf("%.5f", res.Success)}
			}
		}(wi)
	}

	// enqueue jobs
	go func() {
		for _, N := range Ns {
			var Ks []int
			if v, ok := cfgKs[N]; ok {
				Ks = v
			} else {
				for K := 1; K < N; K++ {
					Ks = append(Ks, K)
				}
			}
			for _, K := range Ks {
				R := N - K
				// include e=0 up to R (inclusive)
				for e := 0; e <= R; e++ {
					jobs <- job{N: N, K: K, e: e}
				}
			}
		}
		close(jobs)
	}()

	// wait for workers then close writer
	wg.Wait()
	close(lines)
}

// ---------- small helpers (duplicated from run_offline_pipeline) ----------

func parseIntList(s string) []int {
	toks := strings.Split(s, ",")
	out := make([]int, 0, len(toks))
	for _, t := range toks {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		v, _ := strconv.Atoi(t)
		out = append(out, v)
	}
	return out
}

func parseKsMode(s string) map[int][]int {
	out := map[int][]int{}
	if s == "all" || s == "" {
		return out
	}
	if !strings.HasPrefix(s, "subset:") {
		return out
	}
	rest := strings.TrimPrefix(s, "subset:")
	for _, part := range strings.Split(rest, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
		if len(kv) != 2 {
			continue
		}
		N, _ := strconv.Atoi(kv[0])
		ranges := strings.Split(kv[1], ";")
		var Ks []int
		for _, rg := range ranges {
			rg = strings.TrimSpace(rg)
			if rg == "" {
				continue
			}
			ab := strings.SplitN(rg, "-", 2)
			if len(ab) == 2 {
				a, _ := strconv.Atoi(ab[0])
				b, _ := strconv.Atoi(ab[1])
				if a > b {
					a, b = b, a
				}
				for k := a; k <= b; k++ {
					Ks = append(Ks, k)
				}
			} else {
				v, _ := strconv.Atoi(ab[0])
				Ks = append(Ks, v)
			}
		}
		sort.Ints(Ks)
		out[N] = Ks
	}
	return out
}

func buildEpsGridBand(center, W, S float64) []float64 {
	a := clamp(center-W, 0.0, 0.5)
	b := clamp(center+W, 0.0, 0.5)
	// We only support a practical grid at 1e-6 resolution to keep compute bounded.
	// If S is smaller than 1e-6, clamp to 1e-6; values are rounded to 1e-6 anyway.
	if S <= 0 {
		S = 0.005
	}
	// Cap the total number of grid points to keep runtime tractable.
	const maxPts = 201
	band := b - a
	if band < 0 {
		band = 0
	}
	// Compute a step that yields at most maxPts samples.
	minStep := band / float64(maxPts-1)
	if minStep < 1e-6 {
		minStep = 1e-6
	}
	if S < minStep {
		S = minStep
	}
	// Round endpoints to 1e-6 grid to avoid floating accumulation error.
	ai := int(math.Round(a * 1e6))
	bi := int(math.Round(b * 1e6))
	si := int(math.Round(S * 1e6))
	if si <= 0 {
		si = 1
	}
	var out []float64
	for x := ai; x <= bi; x += si {
		out = append(out, float64(x)/1e6)
	}
	return out
}
func clamp(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}
func itoa(i int) string { return strconv.Itoa(i) }
func log2(n int) int {
	p := 0
	for (1 << p) < n {
		p++
	}
	return p
}
func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func majorityA(Asets [][]int, N, K int) []int {
	cnt := make([]int, N)
	for _, A := range Asets {
		for _, i := range A {
			cnt[i]++
		}
	}
	type cand struct{ idx, cnt int }
	cands := make([]cand, 0, N)
	for i := 0; i < N; i++ {
		if cnt[i] > 0 {
			cands = append(cands, cand{i, cnt[i]})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].cnt != cands[j].cnt {
			return cands[i].cnt > cands[j].cnt
		}
		return cands[i].idx < cands[j].idx
	})
	out := make([]int, K)
	for i := 0; i < K; i++ {
		out[i] = cands[i].idx
	}
	sort.Ints(out)
	return out
}

func sha256HexOfJSON(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// duplicated helpers
func fecPolarGeneratorBool(n int) [][]bool {
	G := [][]bool{{true}}
	for t := 0; t < n; t++ {
		a := len(G)
		b := len(G[0])
		NG := make([][]bool, 2*a)
		for i := range NG {
			NG[i] = make([]bool, 2*b)
		}
		for i := 0; i < a; i++ {
			for j := 0; j < b; j++ {
				NG[i][j] = G[i][j]
				NG[a+i][j] = G[i][j]
				NG[a+i][b+j] = G[i][j]
			}
		}
		G = NG
	}
	return G
}
func extract(G [][]bool, rows, cols []int) [][]bool {
	out := make([][]bool, len(rows))
	for i := range rows {
		r := make([]bool, len(cols))
		for j := range cols {
			r[j] = G[rows[i]][cols[j]]
		}
		out[i] = r
	}
	return out
}
func complement(A []int, N int) []int {
	in := make([]bool, N)
	for _, v := range A {
		in[v] = true
	}
	out := make([]int, 0, N-len(A))
	for i := 0; i < N; i++ {
		if !in[i] {
			out = append(out, i)
		}
	}
	return out
}
func invertBoolMatrixGF2Local(A [][]bool) ([][]bool, bool) {
	n := len(A)
	if n == 0 {
		return nil, false
	}
	m := len(A[0])
	if n != m {
		return nil, false
	}
	B := make([][]bool, n)
	for i := 0; i < n; i++ {
		row := make([]bool, 2*n)
		copy(row, A[i])
		row[n+i] = true
		B[i] = row
	}
	r := 0
	for c := 0; c < n && r < n; c++ {
		pr := -1
		for i := r; i < n; i++ {
			if B[i][c] {
				pr = i
				break
			}
		}
		if pr == -1 {
			continue
		}
		if pr != r {
			B[r], B[pr] = B[pr], B[r]
		}
		for i := 0; i < n; i++ {
			if i == r {
				continue
			}
			if B[i][c] {
				for j := c; j < 2*n; j++ {
					B[i][j] = B[i][j] != B[r][j]
				}
			}
		}
		r++
	}
	if r != n {
		return nil, false
	}
	inv := make([][]bool, n)
	for i := 0; i < n; i++ {
		inv[i] = append([]bool(nil), B[i][n:]...)
	}
	return inv, true
}
func matMulGF2(A, B [][]bool) [][]bool {
	n := len(A)
	k := len(A[0])
	m := len(B[0])
	out := make([][]bool, n)
	for i := 0; i < n; i++ {
		row := make([]bool, m)
		for j := 0; j < m; j++ {
			s := false
			for t := 0; t < k; t++ {
				if A[i][t] && B[t][j] {
					s = !s
				}
			}
			row[j] = s
		}
		out[i] = row
	}
	return out
}
func parityOrderCoverageHeuristic(Gpar [][]uint64, K int, e int, samples int, seed int64) []int {
	R := len(Gpar)
	rng := rand.New(rand.NewSource(seed))
	rowSets := make([][]int, samples)
	for s := 0; s < samples; s++ {
		rowSets[s] = sampleRows(K, e, rng)
	}
	covered := make([]bool, K)
	used := make([]bool, R)
	order := make([]int, 0, R)
	for len(order) < R {
		best := -1
		bestScore := -1
		for j := 0; j < R; j++ {
			if used[j] {
				continue
			}
			score := 0
			for s := 0; s < samples; s++ {
				gain := 0
				for _, r := range rowSets[s] {
					if covered[r] {
						continue
					}
					if ((Gpar[j][r>>6] >> uint(r&63)) & 1) == 1 {
						gain = 1
						break
					}
				}
				score += gain
			}
			if score > bestScore {
				bestScore = score
				best = j
			}
		}
		if best == -1 {
			break
		}
		used[best] = true
		order = append(order, best)
		for r := 0; r < K; r++ {
			if ((Gpar[best][r>>6] >> uint(r&63)) & 1) == 1 {
				covered[r] = true
			}
		}
	}
	for j := 0; j < R; j++ {
		if !used[j] {
			order = append(order, j)
		}
	}
	return order
}
func sampleRows(K, e int, rng *rand.Rand) []int {
	idx := rng.Perm(K)
	if e > K {
		e = K
	}
	out := make([]int, e)
	copy(out, idx[:e])
	sort.Ints(out)
	return out
}

type mcResult struct {
	Success  float64
	RankHist map[int]int
	Trials   int
}

func evalSuccessRates(N, K int, Gpar [][]uint64, trials, e int, rng *rand.Rand) mcResult {
	R := len(Gpar)
	succ := 0
	hist := make(map[int]int)
	for t := 0; t < trials; t++ {
		drops := rng.Perm(N)[:e]
		lostSrc := make([]int, 0, e)
		recvPar := make([]int, 0, R)
		lostPar := make([]bool, R)
		for _, d := range drops {
			if d < K {
				lostSrc = append(lostSrc, d)
			} else {
				lostPar[d-K] = true
			}
		}
		for j := 0; j < R; j++ {
			if !lostPar[j] {
				recvPar = append(recvPar, j)
			}
		}
		rnk := rankOfSubmatrix(Gpar, K, lostSrc, recvPar)
		hist[rnk]++
		if rnk == len(lostSrc) {
			succ++
		}
	}
	return mcResult{Success: float64(succ) / float64(trials), RankHist: hist, Trials: trials}
}
func rankOfSubmatrix(Gpar [][]uint64, K int, S []int, P []int) int {
	s := len(S)
	if s == 0 {
		return 0
	}
	pos := make(map[int]int, s)
	for i, r := range S {
		pos[r] = i
	}
	cols := make([]uint64, len(P))
	for ci, j := range P {
		var mask uint64
		for _, r := range S {
			if ((Gpar[j][r>>6] >> uint(r&63)) & 1) == 1 {
				mask |= 1 << uint(pos[r])
			}
		}
		cols[ci] = mask
	}
	rank := 0
	for bit := 0; bit < s && rank < len(cols); bit++ {
		pivot := -1
		for j := rank; j < len(cols); j++ {
			if (cols[j]>>uint(bit))&1 == 1 {
				pivot = j
				break
			}
		}
		if pivot == -1 {
			continue
		}
		cols[rank], cols[pivot] = cols[pivot], cols[rank]
		pb := cols[rank]
		for j := 0; j < len(cols); j++ {
			if j == rank {
				continue
			}
			if ((cols[j] >> uint(bit)) & 1) == 1 {
				cols[j] ^= pb
			}
		}
		rank++
	}
	return rank
}
func shortTableID(indexing string, epsGrid []float64, Ahash, orderHash string) string {
	b, _ := json.Marshal(struct {
		Idx string
		Eg  []float64
		Ah  string
		Oh  string
	}{indexing, epsGrid, Ahash, orderHash})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", path, err)
		os.Exit(1)
	}
}
