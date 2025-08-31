package fec

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// NewPacketPolarParamsFromArtifacts loads precomputed artifacts for a fixed (N,K,e)
// from baseDir/tables/N{N}_K{K}_e{e}/table_*/ and constructs PacketPolarParams.
// It prefers the most recently modified table_* directory. The artifacts contain:
//   - A.json:    info set indices (len K)
//   - parity_order.json: permutation of [0..R-1] specifying parity emission order
//   - meta.json: optional; if present, its band_center is used to fill Epsilon
func NewPacketPolarParamsFromArtifacts(baseDir string, N, K, e, maxLen int) (*PacketPolarParams, error) {
	if N <= 0 || K <= 0 || K >= N {
		return nil, errors.New("invalid N,K")
	}
	if N&(N-1) != 0 {
		return nil, errors.New("n must be power of two")
	}
	cfgDir := filepath.Join(baseDir, fmt.Sprintf("N%[1]d_K%[2]d_e%[3]d", N, K, e))
	entries, err := os.ReadDir(cfgDir)
	if err != nil {
		return nil, fmt.Errorf("read config dir: %w", err)
	}
	type tableDir struct {
		name string
		mod  int64
	}
	cands := make([]tableDir, 0)
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		name := ent.Name()
		if len(name) < 6 || name[:6] != "table_" {
			continue
		}
		info, err := ent.Info()
		if err != nil {
			continue
		}
		cands = append(cands, tableDir{name: name, mod: info.ModTime().UnixNano()})
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("no table_* dirs under %s", cfgDir)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].mod > cands[j].mod })
	chosen := filepath.Join(cfgDir, cands[0].name)

	// Read A.json
	var A []int
	if b, err := os.ReadFile(filepath.Join(chosen, "A.json")); err == nil {
		if err := json.Unmarshal(b, &A); err != nil {
			return nil, fmt.Errorf("parse A.json: %w", err)
		}
	} else {
		return nil, fmt.Errorf("read A.json: %w", err)
	}
	if len(A) != K {
		return nil, fmt.Errorf("a.json length mismatch: expected K=%d got %d", K, len(A))
	}
	// Build Ac (complement ascending)
	inA := make([]bool, N)
	for _, v := range A {
		if v < 0 || v >= N {
			return nil, fmt.Errorf("a index out of range: %d", v)
		}
		inA[v] = true
	}
	R := N - K
	Ac := make([]int, 0, R)
	for i := 0; i < N; i++ {
		if !inA[i] {
			Ac = append(Ac, i)
		}
	}

	// Build Gpar canonically from A,Ac
	// n = log2 N
	n := 0
	for (1 << n) < N {
		n++
	}
	G := polarGeneratorBool(n)
	// Extract G_AA and G_AAc
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
	invGAA, ok := invertBoolMatrixGF2(GAA)
	if !ok {
		return nil, errors.New("G_AA not invertible (artifacts)")
	}
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
	// Build canonical Gpar rows (R rows), column-major from P
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

	// Read parity_order.json and reorder Gpar accordingly (so index j maps to optimized row)
	var order []int
	if b, err := os.ReadFile(filepath.Join(chosen, "parity_order.json")); err == nil {
		if err := json.Unmarshal(b, &order); err != nil {
			return nil, fmt.Errorf("parse parity_order.json: %w", err)
		}
		if len(order) != R {
			return nil, fmt.Errorf("parity_order length mismatch: expected R=%d got %d", R, len(order))
		}
		// validate permutation and apply
		seen := make([]bool, R)
		GparOrdered := make([][]uint64, R)
		for j := 0; j < R; j++ {
			idx := order[j]
			if idx < 0 || idx >= R || seen[idx] {
				return nil, errors.New("parity_order is not a valid permutation")
			}
			seen[idx] = true
			GparOrdered[j] = Gpar[idx]
		}
		Gpar = GparOrdered
	} else {
		// parity order missing is acceptable; use canonical
	}

	// Optional: read meta.json to set Epsilon (band_center)
	eps := 0.0
	if b, err := os.ReadFile(filepath.Join(chosen, "meta.json")); err == nil {
		var meta struct {
			BandCenter float64 `json:"band_center"`
		}
		if json.Unmarshal(b, &meta) == nil {
			eps = meta.BandCenter
		}
	}

	p := &PacketPolarParams{
		N: N, K: K, Epsilon: eps, MaxLen: maxLen,
		n: n, R: R, A: append([]int(nil), A...), Ac: append([]int(nil), Ac...), Gpar: Gpar,
	}
	return p, nil
}
