package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/quic-go/quic-go/fec"
)

func main() {
	var N, K, L, trials, workers int
	var epsStart, epsEnd, epsStep float64
	var eListStr string
	var seed int64
	var outRoot string
	flag.IntVar(&N, "N", 32, "block size (power of two)")
	flag.IntVar(&K, "K", 16, "source count")
	flag.IntVar(&L, "L", 1500, "packet length hint")
	flag.Float64Var(&epsStart, "epsStart", 0.16, "epsilon start")
	flag.Float64Var(&epsEnd, "epsEnd", 0.22, "epsilon end")
	flag.Float64Var(&epsStep, "epsStep", 0.01, "epsilon step")
	flag.IntVar(&trials, "trials", 10000, "Monte Carlo trials per e")
	flag.StringVar(&eListStr, "e", "4,5,6", "comma-separated erasure counts")
	flag.IntVar(&workers, "workers", 8, "parallel workers (unused placeholder)")
	flag.Int64Var(&seed, "seed", 12345, "RNG seed")
	flag.StringVar(&outRoot, "out", "tables", "output root directory")
	flag.Parse()

	if N <= 0 || (N&(N-1)) != 0 || K <= 0 || K >= N {
		fatalf("invalid N,K: N=%d K=%d", N, K)
	}
	R := N - K
	epsList := buildEpsGrid(epsStart, epsEnd, epsStep)
	shaZ := sha256.New()

	// Stage A: compute Z and A per epsilon
	Asets := make([][]int, len(epsList))
	for i, eps := range epsList {
		p, err := fec.NewPacketPolarParams(N, K, eps, L)
		if err != nil {
			fatalf("params(eps=%.4f): %v", eps, err)
		}
		Asets[i] = append([]int(nil), p.A...)
		// accumulate hash over A sets to ensure determinism across grid
		b, _ := json.Marshal(p.A)
		shaZ.Write(b)
	}
	zHash := hex.EncodeToString(shaZ.Sum(nil))

	// Stage B: robust A via majority vote + average-Z tie-break (approx by frequency then index)
	counts := make([]int, N)
	for _, A := range Asets {
		for _, idx := range A {
			counts[idx]++
		}
	}
	type cand struct{ idx, cnt int }
	cands := make([]cand, 0, N)
	for i := 0; i < N; i++ {
		if counts[i] > 0 {
			cands = append(cands, cand{idx: i, cnt: counts[i]})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].cnt != cands[j].cnt {
			return cands[i].cnt > cands[j].cnt
		}
		return cands[i].idx < cands[j].idx
	})
	if len(cands) < K {
		fatalf("insufficient candidates to form A: %d < K", len(cands))
	}
	Arob := make([]int, K)
	for i := 0; i < K; i++ {
		Arob[i] = cands[i].idx
	}
	sort.Ints(Arob)
	Ahash := sha256HexOfJSON(Arob)

	// Build Gpar from robust A (epsilon-independent once A is fixed)
	// Reuse NewPacketPolarParams but with representative eps (mid point) so that A is consistent
	if _, err := fec.NewPacketPolarParams(N, K, mean(epsList), L); err != nil {
		fatalf("params(mid): %v", err)
	}
	// Override with robust A by rebuilding generator from scratch
	// Simpler: rebuild via fec internals by constructing P from Arob
	G := fecPolarGeneratorBool(log2(N))
	GAA := extract(G, Arob, Arob)
	GAAc := extract(G, Arob, complement(Arob, N))
	invGAA, ok := invertBoolMatrixGF2Local(GAA)
	if !ok {
		fatalf("G_AA not invertible for robust A")
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

	// Stage C: parity ordering heuristic (coverage-based marginal gain for e* = median of e list)
	eTargets := parseEList(eListStr)
	eStar := eTargets[len(eTargets)/2]
	order := parityOrderCoverageHeuristic(Gpar, K, eStar, 2000, seed)
	orderHash := sha256HexOfJSON(order)

	// Stage D: Monte Carlo success for each e
	rng := rand.New(rand.NewSource(seed))
	results := make(map[int]mcResult)
	for _, e := range eTargets {
		res := evalSuccessRates(N, K, Gpar, trials, e, rng)
		results[e] = res
	}

	// Stage E: write outputs under tables/N{N}_K{K}/table_{id}/
	tableID := time.Now().UTC().Format("20060102T150405Z")
	base := filepath.Join(outRoot, fmt.Sprintf("N%d_K%d", N, K), "table_"+tableID)
	mustMkdirAll(base)
	mustWriteJSON(filepath.Join(base, "A.json"), Arob)
	mustWriteJSON(filepath.Join(base, "parity_order.json"), order)
	meta := map[string]any{
		"version":             "v1",
		"indexing":            "natural",
		"epsilon_grid":        epsList,
		"band_policy":         "majority-vote+coverage",
		"upo":                 "disabled",
		"urs_base":            "n/a",
		"optimization_target": "max_E_rank",
		"parity_order_policy": "coverage-marginal-gain",
		"interleaver_depth":   0,
		"seed":                seed,
		"A_hash":              "sha256:" + Ahash,
		"parity_order_hash":   "sha256:" + orderHash,
	}
	mustWriteJSON(filepath.Join(base, "meta.json"), meta)

	// Print summary for copy-paste into report
	fmt.Printf("Stage A: Z-table hash: %s\n", zHash)
	fmt.Printf("Stage B: A set (len=%d): %v\n", len(Arob), Arob)
	fmt.Printf("A_hash: sha256:%s\n", Ahash)
	fmt.Printf("Stage C: parity_order (len=%d): %v\n", len(order), order)
	fmt.Printf("parity_order_hash: sha256:%s\n", orderHash)
	fmt.Println("Stage D: Success Rates and Rank Histograms")
	for _, e := range eTargets {
		fmt.Printf("e=%d: %s\n", e, results[e].String())
	}
	fmt.Printf("Stage E: saved A.json, parity_order.json, meta.json under: %s\n", base)
}

// ---------- helpers ----------

func fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
func mustMkdirAll(p string) {
	if err := os.MkdirAll(p, 0o755); err != nil {
		fatalf("mkdir %s: %v", p, err)
	}
}
func mustWriteJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func buildEpsGrid(a, b, step float64) []float64 {
	if step <= 0 {
		step = 0.01
	}
	var out []float64
	for e := a; e <= b+1e-12; e += step {
		out = append(out, math.Round(e*1e4)/1e4)
	}
	return out
}

func parseEList(s string) []int {
	var out []int
	for _, tok := range strings.Split(s, ",") {
		if tok == "" {
			continue
		}
		var v int
		fmt.Sscanf(strings.TrimSpace(tok), "%d", &v)
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func log2(n int) int {
	p := 0
	for (1 << p) < n {
		p++
	}
	return p
}

func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := 0.0
	for _, v := range xs {
		s += v
	}
	return s / float64(len(xs))
}

func sha256HexOfJSON(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Local copies of small fec helpers to avoid exporting internals
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
	// augment with identity
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

// coverage heuristic for parity ordering
func parityOrderCoverageHeuristic(Gpar [][]uint64, K int, e int, samples int, seed int64) []int {
	R := len(Gpar)
	rng := rand.New(rand.NewSource(seed))
	// sample S sets of rows (lost sources)
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
		// update covered set approximately (greedy): mark rows hit by this column
		for r := 0; r < K; r++ {
			if ((Gpar[best][r>>6] >> uint(r&63)) & 1) == 1 {
				covered[r] = true
			}
		}
	}
	// append any leftovers
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

func (m mcResult) String() string {
	ks := make([]int, 0, len(m.RankHist))
	for k := range m.RankHist {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	var b strings.Builder
	fmt.Fprintf(&b, "success=%.2f%% ", m.Success*100)
	b.WriteString("rank_hist={")
	for i, k := range ks {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%d:%d", k, m.RankHist[k])
	}
	b.WriteString("}")
	return b.String()
}

func evalSuccessRates(N, K int, Gpar [][]uint64, trials, e int, rng *rand.Rand) mcResult {
	R := len(Gpar)
	succ := 0
	hist := make(map[int]int)
	for t := 0; t < trials; t++ {
		// choose e drops among N
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

// compute rank of H[S,P] where columns are parity columns and rows S subset of sources
func rankOfSubmatrix(Gpar [][]uint64, K int, S []int, P []int) int {
	// map S rows to 0..s-1 and build column bitmasks within uint64
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
	// Gaussian elimination on bit columns (over rows)
	rank := 0
	for bit := 0; bit < s && rank < len(cols); bit++ {
		// find a col with this bit set from rank..end
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
		// eliminate this bit from all other columns
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
