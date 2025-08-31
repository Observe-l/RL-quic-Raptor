package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
)

func generateMap(nbits int) []int {
	r := rand.New(rand.NewSource(1)) // fixed seed for stability
	return r.Perm(nbits)
}

func saveRandomMap(filePath string, m []int) error {
	vals64 := make([]int64, len(m))
	for i, v := range m {
		vals64[i] = int64(v)
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, vals64); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(filePath, buf.Bytes(), 0o644)
}

func main() {
	var nbits int
	var out string
	flag.IntVar(&nbits, "n", 1024, "codeword length in bits (must be >0)")
	flag.StringVar(&out, "o", "", "output file path (default: fec/random_map_<n>.bin)")
	flag.Parse()
	if nbits <= 0 {
		fmt.Fprintln(os.Stderr, "nbits must be > 0")
		os.Exit(1)
	}
	if out == "" {
		out = filepath.Join("fec", fmt.Sprintf("random_map_%d.bin", nbits))
	}
	m := generateMap(nbits)
	if err := saveRandomMap(out, m); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d entries)\n", out, len(m))
}
