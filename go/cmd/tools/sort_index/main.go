package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type rec struct {
	N, K, e int
	fields  []string
}

func main() {
	var path string
	flag.StringVar(&path, "path", "tables/index.csv", "path to index.csv")
	flag.Parse()

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", path, err)
		os.Exit(1)
	}
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // allow variable to handle partial lines
	recs, err := r.ReadAll()
	_ = f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}
	if len(recs) == 0 {
		fmt.Fprintf(os.Stderr, "empty csv: %s\n", path)
		os.Exit(1)
	}
	// skip any leading blank lines
	i0 := 0
	for i0 < len(recs) && (len(recs[i0]) == 0 || (len(recs[i0]) == 1 && strings.TrimSpace(recs[i0][0]) == "")) {
		i0++
	}
	if i0 >= len(recs) {
		fmt.Fprintf(os.Stderr, "no header in %s\n", path)
		os.Exit(1)
	}
	head := recs[i0]
	headLen := len(head)
	var rows []rec
	for i := i0 + 1; i < len(recs); i++ {
		row := recs[i]
		if len(row) < 3 {
			continue
		}
		// normalize row to header length
		if len(row) < headLen {
			continue
		}
		if len(row) > headLen {
			row = row[:headLen]
		}
		N, _ := strconv.Atoi(strings.TrimSpace(row[0]))
		K, _ := strconv.Atoi(strings.TrimSpace(row[1]))
		e, _ := strconv.Atoi(strings.TrimSpace(row[2]))
		rows = append(rows, rec{N: N, K: K, e: e, fields: row})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].N != rows[j].N {
			return rows[i].N < rows[j].N
		}
		if rows[i].K != rows[j].K {
			return rows[i].K < rows[j].K
		}
		return rows[i].e < rows[j].e
	})

	tmp := filepath.Join(filepath.Dir(path), ".index.csv.tmp")
	out, err := os.Create(tmp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", tmp, err)
		os.Exit(1)
	}
	w := csv.NewWriter(out)
	_ = w.Write(head)
	for _, rr := range rows {
		_ = w.Write(rr.fields)
	}
	w.Flush()
	_ = out.Close()
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintf(os.Stderr, "rename %s -> %s: %v\n", tmp, path, err)
		os.Exit(1)
	}
	fmt.Printf("sorted %s (%d rows) by N,K,e\n", path, len(rows))
}
