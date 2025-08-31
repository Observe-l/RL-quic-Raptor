package fec

import (
	"errors"
	"math/bits"
	"path/filepath"
	"sort"
)

// BytePolarParams encapsulates a systematic byte-level Polar code over N bytes with K data bytes.
// It reuses packet-level Polar masks (Gpar) and maintains index maps from polar positions to canonical indices.
type BytePolarParams struct {
	N, K    int
	n, R    int
	A, Ac   []int              // ascending
	posInA  []int              // length N, -1 if not in A
	posInAc []int              // length N, -1 if not in Ac
	pp      *PacketPolarParams // packet-level masks with MaxLen=1
	// precomputed contributing K-column indices for each parity row (matching Ac order)
	parityCols [][]int
	// cached factorization per erasure mask key
	factCache map[string]PacketPolarFact
}

// NewBytePolarParamsFromInverted builds params from the inverted reliability table path and caches A under cacheDir.
func NewBytePolarParamsFromInverted(tablePath, cacheDir string, N, K int) (*BytePolarParams, error) {
	if N <= 0 || K <= 0 || K >= N || (N&(N-1)) != 0 {
		return nil, errors.New("invalid N,K")
	}
	// Try cache
	aPath := CacheAPath(cacheDir, N, K)
	var A []int
	if aa, err := LoadA(aPath); err == nil && len(aa) == K {
		A = aa
	} else {
		order, err := LoadInvertedReliabilityTable(tablePath)
		if err != nil {
			return nil, err
		}
		// Build top-K indices by value (order already desc by reliability)
		picks := make([]int, 0, K)
		for _, idx := range order {
			if idx >= 0 && idx < N {
				picks = append(picks, idx)
				if len(picks) == K {
					break
				}
			}
		}
		if len(picks) != K {
			return nil, errors.New("not enough indices in table")
		}
		sort.Ints(picks)
		A = picks
		_ = SaveA(aPath, A)
	}
	pp, err := NewPacketPolarParamsFromA(N, K, A, 1)
	if err != nil {
		return nil, err
	}
	// Build maps
	posInA := make([]int, N)
	posInAc := make([]int, N)
	for i := 0; i < N; i++ {
		posInA[i] = -1
		posInAc[i] = -1
	}
	for i, v := range pp.A {
		posInA[v] = i
	}
	for i, v := range pp.Ac {
		posInAc[v] = i
	}
	// Precompute parity column indices for faster encode
	wordsK := (K + 63) / 64
	parityCols := make([][]int, len(pp.Ac))
	for j := 0; j < len(pp.Ac); j++ {
		row := pp.Gpar[j]
		cols := make([]int, 0, 64)
		for w := 0; w < wordsK; w++ {
			m := row[w]
			for m != 0 {
				tz := trailingZeros64(m)
				idx := (w << 6) + tz
				if idx < K {
					cols = append(cols, idx)
				}
				m &= m - 1
			}
		}
		parityCols[j] = cols
	}
	return &BytePolarParams{N: N, K: K, n: pp.n, R: pp.R, A: pp.A, Ac: pp.Ac, posInA: posInA, posInAc: posInAc, pp: pp, parityCols: parityCols, factCache: make(map[string]PacketPolarFact)}, nil
}

// DefaultInvertedTablePath returns the default tables path.
func DefaultInvertedTablePath() string {
	return filepath.Join("docs", "polar_table_5_3_1_2_1_inverted.txt")
}

// BytePolarEncodeSystematic encodes K source bytes into an N-byte systematic codeword.
func BytePolarEncodeSystematic(p *BytePolarParams, src []byte) ([]byte, error) {
	if len(src) != p.K {
		return nil, errors.New("src length must equal K")
	}
	out := make([]byte, p.N)
	// Place data
	for ai, pos := range p.A {
		out[pos] = src[ai]
	}
	// Compute parity at Ac using precomputed columns
	for j, pos := range p.Ac { // j in [0..R-1]
		var v byte
		for _, idx := range p.parityCols[j] {
			v ^= src[idx]
		}
		out[pos] = v
	}
	return out, nil
}

// BytePolarFastRecover returns K data bytes directly from a full codeword when no loss (systematic fast path).
func BytePolarFastRecover(p *BytePolarParams, codeword []byte) ([]byte, error) {
	if len(codeword) != p.N {
		return nil, errors.New("codeword length mismatch")
	}
	out := make([]byte, p.K)
	for ai, pos := range p.A {
		out[ai] = codeword[pos]
	}
	return out, nil
}

// BytePolarDecodeSystematic decodes data bytes from known codeword bytes using packet-level split-phase on 1-byte payloads.
func BytePolarDecodeSystematic(p *BytePolarParams, codeword []byte, mask []bool) ([]byte, bool, error) {
	if len(codeword) != p.N || len(mask) != p.N {
		return nil, false, errors.New("length mismatch")
	}
	// Fast path: all present
	all := true
	for i := 0; i < p.N; i++ {
		if !mask[i] {
			all = false
			break
		}
	}
	if all {
		b, err := BytePolarFastRecover(p, codeword)
		return b, true, err
	}
	// Build present index list and aligned data rows
	present := make([]int, 0, p.N)
	data := make([][]byte, 0, p.N)
	for r := 0; r < p.N; r++ {
		if !mask[r] {
			continue
		}
		if ai := p.posInA[r]; ai != -1 {
			present = append(present, ai)
			data = append(data, []byte{codeword[r]})
		} else if cj := p.posInAc[r]; cj != -1 {
			present = append(present, p.K+cj)
			data = append(data, []byte{codeword[r]})
		}
	}
	if len(present) < p.K {
		return nil, false, nil
	}
	// Cache factorization per mask key
	key := packMaskKey(mask)
	fact, okF := p.factCache[key]
	if !okF {
		f, _, ok := PacketPolarFactorize(p.pp, present)
		if !ok {
			return nil, false, nil
		}
		p.factCache[key] = f
		fact = f
	}
	outSlices, _ := PacketPolarSolveWithFact(p.pp, fact, data)
	out := make([]byte, p.K)
	for i := 0; i < p.K; i++ {
		out[i] = outSlices[i][0]
	}
	return out, true, nil
}

func trailingZeros64(x uint64) int { return bits.TrailingZeros64(x) }

// packMaskKey converts a []bool mask into a compact string key for caching.
func packMaskKey(mask []bool) string {
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
