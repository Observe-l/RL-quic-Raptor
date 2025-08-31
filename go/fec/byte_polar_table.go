package fec

import (
	"bufio"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// LoadInvertedReliabilityTable reads a text table with lines: index value, where larger value is more reliable.
// Returns indices sorted by reliability DESC (tie-breaker: smaller index first).
func LoadInvertedReliabilityTable(path string) ([]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type row struct {
		idx int
		val int64
	}
	rows := make([]row, 0, 2048)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fs := strings.Fields(line)
		if len(fs) < 2 {
			continue
		}
		i, e1 := strconv.Atoi(fs[0])
		v, e2 := strconv.ParseInt(fs[1], 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		rows = append(rows, row{idx: i, val: v})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].val == rows[j].val {
			return rows[i].idx < rows[j].idx
		}
		return rows[i].val > rows[j].val
	})
	out := make([]int, len(rows))
	for i := range rows {
		out[i] = rows[i].idx
	}
	return out, nil
}

// CacheAPath returns the cache filename for A.
func CacheAPath(cacheDir string, N, K int) string {
	if cacheDir == "" {
		cacheDir = "cache"
	}
	return filepath.Join(cacheDir, "polar_A_N"+strconv.Itoa(N)+"_K"+strconv.Itoa(K)+".bin")
}

// SaveA writes A as little-endian int32.
func SaveA(path string, A []int) error {
	if len(A) == 0 {
		return errors.New("empty A")
	}
	b := make([]byte, len(A)*4)
	for i, v := range A {
		binary.LittleEndian.PutUint32(b[i*4:], uint32(v))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// LoadA reads A saved by SaveA.
func LoadA(path string) ([]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b)%4 != 0 {
		return nil, errors.New("invalid A cache")
	}
	n := len(b) / 4
	A := make([]int, n)
	for i := 0; i < n; i++ {
		A[i] = int(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return A, nil
}

// BuildGColsForIndices builds boolean columns of G_N for the provided indices.
func BuildGColsForIndices(n int, indices []int) [][]bool {
	N := 1 << n
	cols := make([][]bool, len(indices))
	for c, j := range indices {
		u := make([]bool, N)
		u[j] = true
		for s := 0; s < n; s++ {
			block := 1 << (s + 1)
			half := 1 << s
			for start := 0; start < N; start += block {
				for k := 0; k < half; k++ {
					i1 := start + k
					i2 := i1 + half
					u[i1] = u[i1] != u[i2]
				}
			}
		}
		cols[c] = u
	}
	return cols
}
