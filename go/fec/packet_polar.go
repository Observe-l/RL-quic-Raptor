package fec

import (
	"errors"
	"math"
	"time"
)

// Packet-level Polar over GF(2). Systematic code with K sources and R=N-K parities.

type PacketPolarParams struct {
	N, K    int
	Epsilon float64
	MaxLen  int

	// Derived
	n    int
	R    int
	A    []int      // info set indices in [0..N-1], ascending
	Ac   []int      // parity set indices
	Gpar [][]uint64 // R rows, each a bitset over K sources (columns)
}

// NewPacketPolarParams builds params for packet-level polar code at given N,K (N must be power of two).
func NewPacketPolarParams(N, K int, eps float64, maxLen int) (*PacketPolarParams, error) {
	if N <= 0 || K <= 0 || K >= N {
		return nil, errors.New("invalid N,K")
	}
	// check power of two
	if N&(N-1) != 0 {
		return nil, errors.New("n must be power of two")
	}
	// n = log2 N
	n := 0
	for (1 << n) < N {
		n++
	}
	// 1) Choose info set A via BEC Bhattacharyya recursion
	z := bhattacharyyaBEC(N, eps)
	idx := make([]int, N)
	for i := range idx {
		idx[i] = i
	}
	// partial sort: pick K smallest Z
	// simple selection sort for small N
	for i := 0; i < K; i++ {
		minj := i
		for j := i + 1; j < N; j++ {
			if z[idx[j]] < z[idx[minj]] {
				minj = j
			}
		}
		idx[i], idx[minj] = idx[minj], idx[i]
	}
	A := append([]int(nil), idx[:K]...)
	// sort A ascending for stable column order
	for i := 0; i < K; i++ {
		for j := i + 1; j < K; j++ {
			if A[j] < A[i] {
				A[i], A[j] = A[j], A[i]
			}
		}
	}
	return NewPacketPolarParamsFromA(N, K, A, maxLen)
}

// Encode produces R parity packets (with indices K..N-1 in the canonical order).
func PacketPolarEncode(p *PacketPolarParams, src [][]byte) (parity [][]byte) {
	if len(src) != p.K {
		panic("src length must equal K")
	}
	L := p.MaxLen
	parity = make([][]byte, p.R)
	for r := 0; r < p.R; r++ {
		out := make([]byte, L)
		mask := p.Gpar[r]
		for i := 0; i < p.K; i++ {
			if (mask[i>>6]>>uint(i&63))&1 == 1 {
				xorBytes(out, src[i])
			}
		}
		parity[r] = out
	}
	return parity
}

type Packet struct {
	Index int
	Data  []byte
}

// Metrics for split-phase packet-level Polar decoding
type PacketPolarSplitMetrics struct {
	ElimTime     time.Duration // Phase A: matrix elimination time
	ApplyTime    time.Duration // Phase B: replay time on payloads
	Rank         int
	RowSwaps     int
	RowXors      int
	ApplyRowXors int
	BytesXored   int64
}

// PacketPolarDecodeSplit performs a two-phase decode:
// Phase A: run elimination on bitset coefficient rows only, logging SWAP/XOR operations.
// Phase B: replay the same operations on the payload buffers and extract solutions.
func PacketPolarDecodeSplit(p *PacketPolarParams, recv []Packet) ([][]byte, PacketPolarSplitMetrics, bool) {
	var metrics PacketPolarSplitMetrics
	// Build separate matrices: coeff bitsets and data buffers
	m := len(recv)
	wordsK := (p.K + 63) / 64
	coeff := make([][]uint64, 0, m)
	data := make([][]byte, 0, m)
	for _, pkt := range recv {
		v := make([]uint64, wordsK)
		if pkt.Index < p.K {
			i := pkt.Index
			if i < 0 || i >= p.K {
				continue
			}
			v[i>>6] |= 1 << uint(i&63)
		} else {
			j := pkt.Index - p.K
			if j < 0 || j >= p.R {
				continue
			}
			copy(v, p.Gpar[j])
		}
		buf := make([]byte, p.MaxLen)
		copy(buf, pkt.Data)
		coeff = append(coeff, v)
		data = append(data, buf)
	}
	m = len(coeff)
	if m < p.K {
		return nil, metrics, false
	}
	// Operation log
	type op struct {
		kind uint8
		i, j int
	}
	const (
		opSwap uint8 = 0
		opXor  uint8 = 1
	)
	// Reserve capacity ~K*m
	oplog := make([]op, 0, p.K*min(m, p.K))
	pivRow := make([]int, p.K)
	for i := range pivRow {
		pivRow[i] = -1
	}
	// Phase A: forward elimination on coeff only (below pivot), then back substitution (above pivot)
	tA := time.Now()
	r := 0
	for c := 0; c < p.K && r < m; c++ {
		// find pivot row with bit c
		pr := -1
		for i := r; i < m; i++ {
			if ((coeff[i][c>>6] >> uint(c&63)) & 1) == 1 {
				pr = i
				break
			}
		}
		if pr == -1 {
			continue
		}
		if pr != r {
			coeff[r], coeff[pr] = coeff[pr], coeff[r]
			oplog = append(oplog, op{kind: opSwap, i: r, j: pr})
			metrics.RowSwaps++
		}
		pivRow[c] = r
		// eliminate only below pivot in forward pass
		for i := r + 1; i < m; i++ {
			if ((coeff[i][c>>6] >> uint(c&63)) & 1) == 1 {
				for w := 0; w < wordsK; w++ {
					coeff[i][w] ^= coeff[r][w]
				}
				oplog = append(oplog, op{kind: opXor, i: i, j: r})
				metrics.RowXors++
			}
		}
		r++
	}
	// Back substitution: clear above each pivot
	for c := p.K - 1; c >= 0; c-- {
		pr := pivRow[c]
		if pr == -1 {
			continue
		}
		for i := 0; i < pr; i++ {
			if ((coeff[i][c>>6] >> uint(c&63)) & 1) == 1 {
				for w := 0; w < wordsK; w++ {
					coeff[i][w] ^= coeff[pr][w]
				}
				oplog = append(oplog, op{kind: opXor, i: i, j: pr})
				metrics.RowXors++
			}
		}
	}
	metrics.ElimTime = time.Since(tA)
	// rank
	rank := 0
	for c := 0; c < p.K; c++ {
		if pivRow[c] != -1 {
			rank++
		}
	}
	metrics.Rank = rank
	if rank < p.K {
		return nil, metrics, false
	}
	// Phase B: replay on data only
	tB := time.Now()
	for _, opx := range oplog {
		if opx.kind == opSwap {
			data[opx.i], data[opx.j] = data[opx.j], data[opx.i]
		} else {
			xorBytes(data[opx.i], data[opx.j])
			metrics.ApplyRowXors++
			metrics.BytesXored += int64(len(data[opx.i]))
		}
	}
	metrics.ApplyTime = time.Since(tB)
	// Extract outputs by pivot rows
	out := make([][]byte, p.K)
	for i := 0; i < p.K; i++ {
		out[i] = make([]byte, p.MaxLen)
		copy(out[i], data[pivRow[i]])
	}
	return out, metrics, true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Decode attempts to recover all K sources from m received packets.
// Canonical indexing: source i has Index=i (0..K-1), parity j has Index=K+j (0..R-1).
// Returns recovered sources in index order [0..K-1].
func PacketPolarDecode(p *PacketPolarParams, recv []Packet) ([][]byte, bool) {
	out, _, ok := PacketPolarDecodeSplit(p, recv)
	return out, ok
}

// Utilities

func polarGeneratorBool(n int) [][]bool {
	G := [][]bool{{true}}
	for t := 0; t < n; t++ {
		a := len(G)
		b := len(G[0])
		NG := make([][]bool, 2*a)
		for i := 0; i < 2*a; i++ {
			NG[i] = make([]bool, 2*b)
		}
		for i := 0; i < a; i++ {
			for j := 0; j < b; j++ {
				NG[i][j] = G[i][j]
				NG[a+i][j] = G[i][j]
				NG[a+i][b+j] = G[i][j]
				// top-right zeros
			}
		}
		G = NG
	}
	return G
}

func bhattacharyyaBEC(N int, eps float64) []float64 {
	// iterative breadth-first over stages
	// Start with length-1 Z=eps, expand n times with transforms [2z - z^2, z^2]
	levels := [][]float64{{eps}}
	for len(levels) < int(math.Log2(float64(N)))+1 {
		prev := levels[len(levels)-1]
		next := make([]float64, 0, len(prev)*2)
		for _, z := range prev {
			z1 := 2*z - z*z
			z2 := z * z
			next = append(next, z1, z2)
		}
		levels = append(levels, next)
	}
	return levels[len(levels)-1]
}

// NewPacketPolarParamsFromA builds params given an explicit information set A (ascending, |A|=K).
// It computes Ac, constructs G_N, forms P = inv(G_AA)*G_AAc, and builds bitset rows Gpar.
func NewPacketPolarParamsFromA(N, K int, A []int, maxLen int) (*PacketPolarParams, error) {
	if N <= 0 || K <= 0 || K >= N {
		return nil, errors.New("invalid N,K")
	}
	if N&(N-1) != 0 {
		return nil, errors.New("n must be power of two")
	}
	if len(A) != K {
		return nil, errors.New("len(A) != K")
	}
	// verify A in range and ascending
	for i := 0; i < K; i++ {
		if A[i] < 0 || A[i] >= N {
			return nil, errors.New("a out of range")
		}
		if i > 0 && A[i] < A[i-1] {
			return nil, errors.New("a must be ascending")
		}
	}
	// n = log2 N
	n := 0
	for (1 << n) < N {
		n++
	}
	R := N - K
	// Build Ac as the complement, ascending
	inA := make([]bool, N)
	for _, v := range A {
		inA[v] = true
	}
	Ac := make([]int, 0, R)
	for i := 0; i < N; i++ {
		if !inA[i] {
			Ac = append(Ac, i)
		}
	}
	// Build G_N (N x N)
	G := polarGeneratorBool(n)
	// Extract G_AA (KxK) and G_AAc (KxR)
	GAA := make([][]bool, K)
	GAAc := make([][]bool, K)
	for i := 0; i < K; i++ {
		row := make([]bool, K)
		for j := 0; j < K; j++ {
			row[j] = G[A[i]][A[j]]
		}
		GAA[i] = row
		row2 := make([]bool, R)
		for j := 0; j < R; j++ {
			row2[j] = G[A[i]][Ac[j]]
		}
		GAAc[i] = row2
	}
	// inv(G_AA)
	invGAA, ok := invertBoolMatrixGF2(GAA)
	if !ok {
		return nil, errors.New("G_AA not invertible")
	}
	// P = inv(G_AA) * G_AAc  => (KxK)*(KxR) = KxR
	P := make([][]bool, K)
	for i := 0; i < K; i++ {
		row := make([]bool, R)
		for j := 0; j < R; j++ {
			s := false
			for t := 0; t < K; t++ {
				if invGAA[i][t] && GAAc[t][j] {
					s = !s
				}
			}
			row[j] = s
		}
		P[i] = row
	}
	// Build Gpar rows (R rows), row j is column j of P (size K)
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
	return &PacketPolarParams{N: N, K: K, Epsilon: 0, MaxLen: maxLen, n: n, R: R, A: append([]int(nil), A...), Ac: Ac, Gpar: Gpar}, nil
}

// byte-wise XOR helper used by multiple schemes
func xorBytes(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// --- Reusable factorization and solver for caching across repeated masks ---

// PacketPolarFact captures the elimination log and pivot rows for a given present set.
type PacketPolarFact struct {
	// Operation log to transform data rows: swap(i,j) or xor(i,j)
	Oplog []struct {
		Kind uint8
		I, J int
	}
	// Pivot row per column in [0..K-1]; -1 if no pivot (rank deficiency)
	PivRow []int
	// Rank achieved during elimination
	Rank int
	// Row positions in codeword order for each row in the factorization (len==m)
	RowPos []int
	// Present indices in canonical indexing (0..K-1 sources, K..N-1 parity)
	Present []int
}

// PacketPolarFactorize builds the coefficient matrix from the present indices and performs
// elimination over GF(2), returning the reusable factorization and metrics.
// The row order is exactly the order of the provided present indices.
func PacketPolarFactorize(p *PacketPolarParams, present []int) (PacketPolarFact, PacketPolarSplitMetrics, bool) {
	var metrics PacketPolarSplitMetrics
	fact := PacketPolarFact{}
	m := len(present)
	if m < p.K {
		return fact, metrics, false
	}
	wordsK := (p.K + 63) / 64
	coeff := make([][]uint64, m)
	rowPos := make([]int, m)
	for r := 0; r < m; r++ {
		v := make([]uint64, wordsK)
		idx := present[r]
		if idx < p.K {
			// source row: identity e_idx
			v[idx>>6] |= 1 << uint(idx&63)
			rowPos[r] = p.A[idx]
		} else {
			j := idx - p.K
			if j < 0 || j >= p.R {
				continue
			}
			copy(v, p.Gpar[j])
			rowPos[r] = p.Ac[j]
		}
		coeff[r] = v
	}
	// Elimination identical to PacketPolarDecodeSplit, recording operations.
	type op struct {
		kind uint8
		i, j int
	}
	const (
		opSwap uint8 = 0
		opXor  uint8 = 1
	)
	oplog := make([]op, 0, p.K*min(m, p.K))
	pivRow := make([]int, p.K)
	for i := range pivRow {
		pivRow[i] = -1
	}
	// Phase A: forward elimination
	tA := time.Now()
	r := 0
	for c := 0; c < p.K && r < m; c++ {
		pr := -1
		for i := r; i < m; i++ {
			if ((coeff[i][c>>6] >> uint(c&63)) & 1) == 1 {
				pr = i
				break
			}
		}
		if pr == -1 {
			continue
		}
		if pr != r {
			coeff[r], coeff[pr] = coeff[pr], coeff[r]
			oplog = append(oplog, op{kind: opSwap, i: r, j: pr})
			metrics.RowSwaps++
			// keep rowPos in sync for Phase B
			rowPos[r], rowPos[pr] = rowPos[pr], rowPos[r]
		}
		pivRow[c] = r
		for i := r + 1; i < m; i++ {
			if ((coeff[i][c>>6] >> uint(c&63)) & 1) == 1 {
				for w := 0; w < wordsK; w++ {
					coeff[i][w] ^= coeff[r][w]
				}
				oplog = append(oplog, op{kind: opXor, i: i, j: r})
				metrics.RowXors++
			}
		}
		r++
	}
	// Back substitution
	for c := p.K - 1; c >= 0; c-- {
		pr := pivRow[c]
		if pr == -1 {
			continue
		}
		for i := 0; i < pr; i++ {
			if ((coeff[i][c>>6] >> uint(c&63)) & 1) == 1 {
				for w := 0; w < wordsK; w++ {
					coeff[i][w] ^= coeff[pr][w]
				}
				oplog = append(oplog, op{kind: opXor, i: i, j: pr})
				metrics.RowXors++
			}
		}
	}
	metrics.ElimTime = time.Since(tA)
	rank := 0
	for c := 0; c < p.K; c++ {
		if pivRow[c] != -1 {
			rank++
		}
	}
	if rank < p.K {
		return fact, metrics, false
	}
	// Build exported fact
	fact.PivRow = pivRow
	fact.Rank = rank
	fact.RowPos = rowPos
	fact.Present = append([]int(nil), present...)
	fact.Oplog = make([]struct {
		Kind uint8
		I, J int
	}, len(oplog))
	for i, opx := range oplog {
		fact.Oplog[i] = struct {
			Kind uint8
			I, J int
		}{Kind: opx.kind, I: opx.i, J: opx.j}
	}
	return fact, metrics, true
}

// PacketPolarSolveWithFact replays the factorization ops on the provided data rows (aligned with fact.RowPos)
// and extracts the K source outputs by pivot rows.
func PacketPolarSolveWithFact(p *PacketPolarParams, fact PacketPolarFact, data [][]byte) ([][]byte, PacketPolarSplitMetrics) {
	var metrics PacketPolarSplitMetrics
	// Phase B: replay ops
	tB := time.Now()
	for _, opx := range fact.Oplog {
		if opx.Kind == 0 { // swap
			data[opx.I], data[opx.J] = data[opx.J], data[opx.I]
		} else { // xor
			xorBytes(data[opx.I], data[opx.J])
			metrics.ApplyRowXors++
			metrics.BytesXored += int64(len(data[opx.I]))
		}
	}
	metrics.ApplyTime = time.Since(tB)
	// Extract outputs
	out := make([][]byte, p.K)
	for i := 0; i < p.K; i++ {
		out[i] = make([]byte, p.MaxLen)
		copy(out[i], data[fact.PivRow[i]])
	}
	return out, metrics
}

// PacketPolarSolveBytesWithFact is a specialized variant for MaxLen==1 payloads.
// It replays the factorization ops on a contiguous []byte rows buffer ordered the
// same way as fact.Present/RowPos and extracts the K source bytes by pivot rows.
func PacketPolarSolveBytesWithFact(p *PacketPolarParams, fact PacketPolarFact, rows []byte) ([]byte, PacketPolarSplitMetrics) {
	var metrics PacketPolarSplitMetrics
	if len(rows) < len(fact.Present) {
		return nil, metrics
	}
	// Replay ops on bytes
	tB := time.Now()
	for _, opx := range fact.Oplog {
		if opx.Kind == 0 { // swap
			rows[opx.I], rows[opx.J] = rows[opx.J], rows[opx.I]
		} else { // xor
			rows[opx.I] ^= rows[opx.J]
			metrics.ApplyRowXors++
			metrics.BytesXored++
		}
	}
	metrics.ApplyTime = time.Since(tB)
	// Extract outputs
	out := make([]byte, p.K)
	for i := 0; i < p.K; i++ {
		pr := fact.PivRow[i]
		if pr >= 0 {
			out[i] = rows[pr]
		}
	}
	return out, metrics
}
