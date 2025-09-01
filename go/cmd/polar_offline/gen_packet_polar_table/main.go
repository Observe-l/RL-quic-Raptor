package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"log"
	"math"
	"sort"

	"github.com/quic-go/quic-go/fec"
)

func main() {
	var N, K, L int
	var out string
	var epsStart, epsEnd, epsStep float64
	flag.IntVar(&N, "N", 32, "block size (power of two)")
	flag.IntVar(&K, "K", 16, "source count")
	flag.IntVar(&L, "L", 1500, "packet length hint (bytes)")
	flag.Float64Var(&epsStart, "epsStart", 0.05, "epsilon range start")
	flag.Float64Var(&epsEnd, "epsEnd", 0.35, "epsilon range end (inclusive)")
	flag.Float64Var(&epsStep, "epsStep", 0.01, "epsilon step")
	flag.StringVar(&out, "out", "packet_polar_table.json", "output JSON path")
	flag.Parse()

	if N <= 0 || K <= 0 || K >= N || (N&(N-1)) != 0 {
		log.Fatalf("invalid N,K: N=%d K=%d", N, K)
	}
	words := (K + 63) / 64
	tbl := &fec.PacketPolarOfflineTable{Version: 1, N: N, K: K, R: N - K, WordsPerRow: words, MaxLenHint: L}

	// enumerate epsilons
	if epsStep <= 0 {
		epsStep = 0.01
	}
	var epsList []float64
	for e := epsStart; e <= epsEnd+1e-12; e += epsStep {
		// normalize to 1e-4 precision to avoid floating drift
		ee := math.Round(e*1e4) / 1e4
		if ee < 0 {
			ee = 0
		}
		if ee > 0.5 {
			ee = 0.5
		}
		epsList = append(epsList, ee)
	}
	sort.Float64s(epsList)
	// de-dup
	epsList = uniqueFloat64(epsList)

	for _, eps := range epsList {
		p, err := fec.NewPacketPolarParams(N, K, eps, L)
		if err != nil {
			log.Fatalf("build params for eps=%.4f: %v", eps, err)
		}
		rowsHex, crc, sha := serializeRows(p.Gpar, words)
		ent := fec.PacketPolarOfflineEntry{Epsilon: eps, A: p.A, Ac: p.Ac, RowsHex: rowsHex, CRC32: crc, SHA256: sha}
		tbl.Entries = append(tbl.Entries, ent)
		fmt.Printf("added eps=%.4f A=%d Ac=%d rows=%d\n", eps, len(p.A), len(p.Ac), len(rowsHex))
	}

	if err := fec.SavePacketPolarTable(out, tbl); err != nil {
		log.Fatalf("save table: %v", err)
	}
	fmt.Printf("wrote %s (%d entries) for N=%d K=%d\n", out, len(tbl.Entries), N, K)
}

func uniqueFloat64(a []float64) []float64 {
	if len(a) == 0 {
		return a
	}
	out := []float64{a[0]}
	for i := 1; i < len(a); i++ {
		if math.Abs(a[i]-out[len(out)-1]) > 1e-9 {
			out = append(out, a[i])
		}
	}
	return out
}

// serializeRows mirrors fec.serializeGparRows (little-endian words, CRC32 and SHA256 of concatenated rows)
func serializeRows(rows [][]uint64, wordsPerRow int) ([]string, uint32, string) {
	crcH := crc32.NewIEEE()
	shaH := sha256.New()
	buf := make([]byte, wordsPerRow*8)
	rowsHex := make([]string, len(rows))
	for i := range rows {
		off := 0
		for w := 0; w < wordsPerRow; w++ {
			v := rows[i][w]
			buf[off+0] = byte(v)
			buf[off+1] = byte(v >> 8)
			buf[off+2] = byte(v >> 16)
			buf[off+3] = byte(v >> 24)
			buf[off+4] = byte(v >> 32)
			buf[off+5] = byte(v >> 40)
			buf[off+6] = byte(v >> 48)
			buf[off+7] = byte(v >> 56)
			off += 8
		}
		crcH.Write(buf)
		shaH.Write(buf)
		rowsHex[i] = hex.EncodeToString(buf)
	}
	return rowsHex, crcH.Sum32(), hex.EncodeToString(shaH.Sum(nil))
}
