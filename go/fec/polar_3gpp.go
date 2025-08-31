package fec

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Load3GPPTable loads a 3GPP frozen set reliability table from a text file with two columns: index, rank.
// Returns indices ordered by DESCENDING rank (larger = more reliable). Lines starting with '#' are ignored.
func Load3GPPTable(path string) ([]int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	type row struct {
		idx int
		val int
	}
	rows := make([]row, 0, 4096)
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		i, err1 := strconv.Atoi(parts[0])
		v, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			continue
		}
		rows = append(rows, row{idx: i, val: v})
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	// Larger rank means more reliable, so sort descending by val
	sort.Slice(rows, func(i, j int) bool { return rows[i].val > rows[j].val })
	ordered := make([]int, len(rows))
	for i := range rows {
		ordered[i] = rows[i].idx
	}
	return ordered, nil
}

// NewPacketPolarParamsFrom3GPP builds parameters using the 3GPP reliability ordering.
// Given N (power of 2), K, and L, it selects the top-K reliable indices from the table and delegates to NewPacketPolarParamsFromA.
func NewPacketPolarParamsFrom3GPP(tablePath string, N, K, maxLen int) (*PacketPolarParams, error) {
	order, err := Load3GPPTable(tablePath)
	if err != nil {
		return nil, err
	}
	if N <= 0 || K <= 0 || K >= N || N&(N-1) != 0 {
		return nil, os.ErrInvalid
	}
	if len(order) < N { // allow larger table; take first N entries
		return nil, os.ErrInvalid
	}
	A := make([]int, 0, K)
	// order is by reliability; we need the indices within [0..N-1]
	// Keep indices < N and take first K
	for _, idx := range order {
		if idx >= 0 && idx < N {
			A = append(A, idx)
			if len(A) == K {
				break
			}
		}
	}
	// sort ascending for internal construction
	sort.Ints(A)
	return NewPacketPolarParamsFromA(N, K, A, maxLen)
}
