package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type row struct {
	N, K, e int
	succ    float64
}

func main() {
	var indexPath, outPath string
	var top int
	flag.StringVar(&indexPath, "index", "tables/index.csv", "path to tables/index.csv")
	flag.StringVar(&outPath, "out", "docs/reports/summary.md", "output markdown path")
	flag.IntVar(&top, "top", 10, "top worst cases per N")
	flag.Parse()

	rows, err := loadRows(indexPath)
	if err != nil {
		fatalf("%v", err)
	}

	byN := map[int][]row{}
	for _, r := range rows {
		byN[r.N] = append(byN[r.N], r)
	}
	Ns := make([]int, 0, len(byN))
	for N := range byN {
		Ns = append(Ns, N)
	}
	sort.Ints(Ns)

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fatalf("mkdir %s: %v", filepath.Dir(outPath), err)
	}
	f, err := os.Create(outPath)
	if err != nil {
		fatalf("create %s: %v", outPath, err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "# Offline sweep summary (worst cases by N)")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Source: tables/index.csv (sorted). Each table lists the top worst cases (lowest success_optimized) at 100k trials.")
	fmt.Fprintln(w, "")
	for _, N := range Ns {
		items := byN[N]
		sort.Slice(items, func(i, j int) bool {
			if items[i].succ != items[j].succ {
				return items[i].succ < items[j].succ
			}
			if items[i].K != items[j].K {
				return items[i].K < items[j].K
			}
			return items[i].e < items[j].e
		})
		limit := top
		if len(items) < limit {
			limit = len(items)
		}
		fmt.Fprintf(w, "## N=%d\n\n", N)
		fmt.Fprintln(w, "| K | e | success_optimized |")
		fmt.Fprintln(w, "|---:|---:|---:|")
		for i := 0; i < limit; i++ {
			it := items[i]
			fmt.Fprintf(w, "| %d | %d | %.5f |\n", it.K, it.e, it.succ)
		}
		fmt.Fprintln(w, "")
	}
	w.Flush()
	fmt.Printf("wrote %s\n", outPath)
}

func loadRows(path string) ([]row, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	// find header and columns
	i0 := 0
	for i0 < len(recs) && (len(recs[i0]) == 0 || (len(recs[i0]) == 1 && strings.TrimSpace(recs[i0][0]) == "")) {
		i0++
	}
	if i0 >= len(recs) {
		return nil, fmt.Errorf("no header in %s", path)
	}
	head := recs[i0]
	col := map[string]int{}
	for i, v := range head {
		col[strings.TrimSpace(v)] = i
	}
	idxN, okN := col["N"]
	idxK, okK := col["K"]
	idxE, okE := col["e"]
	idxS, okS := col["success_optimized"]
	if !(okN && okK && okE && okS) {
		return nil, fmt.Errorf("missing columns in header: have %v", head)
	}
	var out []row
	for i := i0 + 1; i < len(recs); i++ {
		rowv := recs[i]
		if len(rowv) <= idxS {
			continue
		}
		N, _ := strconv.Atoi(strings.TrimSpace(rowv[idxN]))
		K, _ := strconv.Atoi(strings.TrimSpace(rowv[idxK]))
		e, _ := strconv.Atoi(strings.TrimSpace(rowv[idxE]))
		succ, _ := strconv.ParseFloat(strings.TrimSpace(rowv[idxS]), 64)
		out = append(out, row{N: N, K: K, e: e, succ: succ})
	}
	return out, nil
}

func fatalf(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
