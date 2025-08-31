package fec

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
)

// Byte-level interleavers for groups of L packets of length N bytes each.
// These operate independently of the bit-level polar interleaver used in polar.go.

// SlopeParams holds parameters for the slope interleaver over M=N*L bytes.
// Mapping (source to output):
//
//	q = s + L*j           (q in [0..M-1])
//	t = (o + step * q) mod M
//	l = floor(t / N)
//	r = t % N
//	Out[l][r] = In[s][j]
//
// Inverse uses stepInv such that (step * stepInv) % M == 1.
type SlopeParams struct {
	M       int `json:"M"`
	Step    int `json:"s_step"`
	StepInv int `json:"s_inv"`
	Offset  int `json:"o"`
	// Optional: description of how Offset was chosen (e.g., "fixed", "frame_id", "random")
	OPolicy string `json:"o_policy,omitempty"`
	// Optional LUTs to accelerate mapping. If present, functions will use them.
	qToL []int // length M: given q=s+L*j returns l
	qToR []int // length M: given q=s+L*j returns r
	tToS []int // length M: given t=l*N+r returns s
	tToJ []int // length M: given t=l*N+r returns j
}

// NewSlopeParams creates parameters for given N (bytes per packet), L (group size), and offset.
// If step is 0, picks the default step=M-1, which is always coprime to M.
func NewSlopeParams(N, L, offset, step int) (SlopeParams, error) {
	if N <= 0 || L <= 0 {
		return SlopeParams{}, errors.New("invalid N or L")
	}
	M := N * L
	if step == 0 {
		step = M - 1
	}
	if gcd(step, M) != 1 {
		return SlopeParams{}, fmt.Errorf("step (%d) must be coprime with M=%d", step, M)
	}
	inv, ok := modInverse(step, M)
	if !ok {
		return SlopeParams{}, fmt.Errorf("no modular inverse for step=%d mod M=%d", step, M)
	}
	sp := SlopeParams{M: M, Step: step, StepInv: inv, Offset: offset}
	// Precompute LUTs for speed. Offset is fixed per params.
	qToL := make([]int, M)
	qToR := make([]int, M)
	tToS := make([]int, M)
	tToJ := make([]int, M)
	for q := 0; q < M; q++ {
		t := (offset + (step*q)%M) % M
		l := t / N
		r := t % N
		qToL[q] = l
		qToR[q] = r
	}
	for t := 0; t < M; t++ {
		// unsigned mod with positive adjustment
		tp := t - offset
		tp %= M
		if tp < 0 {
			tp += M
		}
		q := (inv * tp) % M
		s := q % L
		j := q / L
		tToS[t] = s
		tToJ[t] = j
	}
	sp.qToL, sp.qToR, sp.tToS, sp.tToJ = qToL, qToR, tToS, tToJ
	return sp, nil
}

// SlopeInterleave applies the slope mapping to a group of L packets (each length N bytes).
func SlopeInterleave(in [][]byte, N int, p SlopeParams) ([][]byte, error) {
	L := len(in)
	if L == 0 || N <= 0 {
		return nil, errors.New("invalid input")
	}
	for i := 0; i < L; i++ {
		if len(in[i]) != N {
			return nil, fmt.Errorf("packet %d length %d != N=%d", i, len(in[i]), N)
		}
	}
	if p.M != N*L {
		return nil, fmt.Errorf("params M=%d mismatch N*L=%d", p.M, N*L)
	}
	out := make([][]byte, L)
	for i := 0; i < L; i++ {
		out[i] = make([]byte, N)
	}
	for s := 0; s < L; s++ {
		src := in[s]
		for j := 0; j < N; j++ {
			q := s + L*j
			l := p.qToL[q]
			r := p.qToR[q]
			out[l][r] = src[j]
		}
	}
	return out, nil
}

// SlopeDeinterleave is the inverse of SlopeInterleave.
func SlopeDeinterleave(in [][]byte, N int, p SlopeParams) ([][]byte, error) {
	L := len(in)
	if L == 0 || N <= 0 {
		return nil, errors.New("invalid input")
	}
	for i := 0; i < L; i++ {
		if len(in[i]) != N {
			return nil, fmt.Errorf("packet %d length %d != N=%d", i, len(in[i]), N)
		}
	}
	if p.M != N*L {
		return nil, fmt.Errorf("params M=%d mismatch N*L=%d", p.M, N*L)
	}
	out := make([][]byte, L)
	for i := 0; i < L; i++ {
		out[i] = make([]byte, N)
	}
	for l := 0; l < L; l++ {
		src := in[l]
		for r := 0; r < N; r++ {
			t := l*N + r
			s := p.tToS[t]
			j := p.tToJ[t]
			out[s][j] = src[r]
		}
	}
	return out, nil
}

// SlopeDeinterleaveKnown returns deinterleaved data and a mask of known bytes (true where at least one copy arrived).
func SlopeDeinterleaveKnown(in [][]byte, N int, p SlopeParams) ([][]byte, [][]bool, error) {
	L := len(in)
	if L == 0 || N <= 0 {
		return nil, nil, errors.New("invalid input")
	}
	for i := 0; i < L; i++ {
		if in[i] != nil && len(in[i]) != N {
			return nil, nil, fmt.Errorf("packet %d length %d != N=%d", i, len(in[i]), N)
		}
	}
	if p.M != N*L {
		return nil, nil, fmt.Errorf("params M=%d mismatch N*L=%d", p.M, N*L)
	}
	out := make([][]byte, L)
	masks := make([][]bool, L)
	for i := 0; i < L; i++ {
		out[i] = make([]byte, N)
		masks[i] = make([]bool, N)
	}
	for l := 0; l < L; l++ {
		if in[l] == nil {
			continue
		}
		src := in[l]
		for r := 0; r < N; r++ {
			t := l*N + r
			s := p.tToS[t]
			j := p.tToJ[t]
			out[s][j] = src[r]
			masks[s][j] = true
		}
	}
	return out, masks, nil
}

// ByteRandomPerm holds a fixed permutation over N byte positions for the random interleaver.
type ByteRandomPerm struct {
	N    int   `json:"N"`
	Perm []int `json:"perm"`
}

// NewByteRandomPerm creates a permutation of [0..N-1] using a fixed seed.
func NewByteRandomPerm(N int, seed int64) ByteRandomPerm {
	r := rand.New(rand.NewSource(seed))
	p := r.Perm(N)
	return ByteRandomPerm{N: N, Perm: p}
}

// Save writes the permutation as little-endian int32 values (compact) or JSON if .json suffix.
func (bp ByteRandomPerm) Save(path string) error {
	if len(path) >= 5 && path[len(path)-5:] == ".json" {
		b, err := json.Marshal(bp)
		if err != nil {
			return err
		}
		return os.WriteFile(path, b, 0o644)
	}
	// binary int32 format: N entries
	buf := make([]byte, 4*len(bp.Perm))
	for i, v := range bp.Perm {
		binary.LittleEndian.PutUint32(buf[i*4:], uint32(v))
	}
	return os.WriteFile(path, buf, 0o644)
}

// LoadByteRandomPerm reads a permutation saved by Save().
func LoadByteRandomPerm(path string, N int) (ByteRandomPerm, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ByteRandomPerm{}, err
	}
	// Try JSON first
	var jp ByteRandomPerm
	if json.Unmarshal(b, &jp) == nil && jp.N > 0 && len(jp.Perm) == jp.N {
		if N != 0 && jp.N != N {
			return ByteRandomPerm{}, fmt.Errorf("perm N=%d does not match expected N=%d", jp.N, N)
		}
		return jp, nil
	}
	if len(b)%4 != 0 {
		return ByteRandomPerm{}, errors.New("invalid perm file length")
	}
	cnt := len(b) / 4
	if N != 0 && cnt != N {
		return ByteRandomPerm{}, fmt.Errorf("perm length=%d != N=%d", cnt, N)
	}
	p := make([]int, cnt)
	for i := 0; i < cnt; i++ {
		p[i] = int(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return ByteRandomPerm{N: cnt, Perm: p}, nil
}

// ByteRandomInterleave interleaves a group using the plan from the design doc:
//
//	S = N/L
//	for s in 0..L-1:
//	  for j in 0..N-1:
//	    u = pi[j]
//	    l = j % L
//	    r = s*S + (j / L)
//	    Out[l][r] = In[s][u]
//
// Requires N % L == 0 and len(pi)==N.
func ByteRandomInterleave(in [][]byte, pi []int) ([][]byte, error) {
	L := len(in)
	if L == 0 {
		return nil, errors.New("empty group")
	}
	N := len(in[0])
	for i := 1; i < L; i++ {
		if len(in[i]) != N {
			return nil, errors.New("non-uniform packet sizes")
		}
	}
	if len(pi) != N {
		return nil, fmt.Errorf("perm length %d != N=%d", len(pi), N)
	}
	if N%L != 0 {
		return nil, fmt.Errorf("n=%d must be divisible by l=%d", N, L)
	}
	S := N / L
	out := make([][]byte, L)
	for i := 0; i < L; i++ {
		out[i] = make([]byte, N)
	}
	for s := 0; s < L; s++ {
		src := in[s]
		for j := 0; j < N; j++ {
			u := pi[j]
			l := j % L
			r := s*S + (j / L)
			out[l][r] = src[u]
		}
	}
	return out, nil
}

// ByteRandomDeinterleave is the inverse of ByteRandomInterleave.
func ByteRandomDeinterleave(in [][]byte, pi []int) ([][]byte, error) {
	L := len(in)
	if L == 0 {
		return nil, errors.New("empty group")
	}
	N := len(in[0])
	for i := 1; i < L; i++ {
		if len(in[i]) != N {
			return nil, errors.New("non-uniform packet sizes")
		}
	}
	if len(pi) != N {
		return nil, fmt.Errorf("perm length %d != N=%d", len(pi), N)
	}
	if N%L != 0 {
		return nil, fmt.Errorf("n=%d must be divisible by l=%d", N, L)
	}
	// Build inverse of pi
	inv := make([]int, N)
	for j := 0; j < N; j++ {
		inv[pi[j]] = j
	}
	S := N / L
	out := make([][]byte, L)
	for i := 0; i < L; i++ {
		out[i] = make([]byte, N)
	}
	for l := 0; l < L; l++ {
		src := in[l]
		for r := 0; r < N; r++ {
			s := r / S
			t := r % S
			j := t*L + l
			u := pi[j]
			out[s][u] = src[r]
		}
	}
	return out, nil
}

// ByteRandomDeinterleaveKnown returns deinterleaved data and a mask of known bytes.
func ByteRandomDeinterleaveKnown(in [][]byte, pi []int) ([][]byte, [][]bool, error) {
	L := len(in)
	if L == 0 {
		return nil, nil, errors.New("empty group")
	}
	N := 0
	for i := 0; i < L; i++ {
		if in[i] != nil {
			N = len(in[i])
			break
		}
	}
	if N == 0 {
		return nil, nil, errors.New("all packets missing")
	}
	for i := 0; i < L; i++ {
		if in[i] != nil && len(in[i]) != N {
			return nil, nil, errors.New("non-uniform packet sizes")
		}
	}
	if len(pi) != N {
		return nil, nil, fmt.Errorf("perm length %d != N=%d", len(pi), N)
	}
	if N%L != 0 {
		return nil, nil, fmt.Errorf("n=%d must be divisible by l=%d", N, L)
	}
	inv := make([]int, N)
	for j := 0; j < N; j++ {
		inv[pi[j]] = j
	}
	S := N / L
	out := make([][]byte, L)
	masks := make([][]bool, L)
	for i := 0; i < L; i++ {
		out[i] = make([]byte, N)
		masks[i] = make([]bool, N)
	}
	for l := 0; l < L; l++ {
		if in[l] == nil {
			continue
		}
		src := in[l]
		for r := 0; r < N; r++ {
			s := r / S
			t := r % S
			j := t*L + l
			u := pi[j]
			out[s][u] = src[r]
			masks[s][u] = true
		}
	}
	return out, masks, nil
}

// SaveSlopeParams stores slope parameters as JSON.
func SaveSlopeParams(path string, p SlopeParams) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// LoadSlopeParams loads slope parameters from JSON.
func LoadSlopeParams(path string) (SlopeParams, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return SlopeParams{}, err
	}
	var p SlopeParams
	if err := json.Unmarshal(b, &p); err != nil {
		return SlopeParams{}, err
	}
	if p.M <= 0 || p.Step <= 0 || p.StepInv <= 0 {
		return SlopeParams{}, errors.New("invalid slope params")
	}
	// Quick consistency check
	if (p.Step*p.StepInv)%p.M != ((1%p.M)+p.M)%p.M {
		return SlopeParams{}, errors.New("slope params not invertible")
	}
	return p, nil
}

// --- helpers ---

func gcd(a, b int) int {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}
	for b != 0 {
		a, b = b, a%b
	}
	if a < 0 {
		return -a
	}
	return a
}

// modInverse computes x such that (a*x) % m == 1, if it exists.
func modInverse(a, m int) (int, bool) {
	t, newT := 0, 1
	r, newR := m, a%m
	for newR != 0 {
		q := r / newR
		t, newT = newT, t-q*newT
		r, newR = newR, r-q*newR
	}
	if r != 1 {
		return 0, false
	}
	if t < 0 {
		t += m
	}
	return t, true
}
