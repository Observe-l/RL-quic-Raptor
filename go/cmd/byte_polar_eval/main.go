package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go/fec"
)

func chunk(data []byte, n int) [][]byte {
	var out [][]byte
	for i := 0; i < len(data); i += n {
		end := i + n
		if end > len(data) {
			end = len(data)
		}
		b := make([]byte, n)
		copy(b, data[i:end])
		out = append(out, b)
	}
	return out
}

func main() {
	var (
		inPath  string
		outPath string
		inter   string
		L       int
		lossP   float64
		seed    int64
		table   string
		kbytes  int
	)
	flag.StringVar(&inPath, "in", "test_data/train_FD001.txt", "input file path")
	flag.StringVar(&outPath, "out", "test_data/byte_polar_decode.txt", "output decoded file path")
	flag.StringVar(&inter, "interleaver", "slope", "interleaver: slope|random")
	flag.IntVar(&L, "L", 32, "group size (packets)")
	flag.Float64Var(&lossP, "ploss", 0.10, "packet erasure probability")
	flag.Int64Var(&seed, "seed", 12345, "random seed for loss and random interleaver")
	flag.StringVar(&table, "table", filepath.Join("docs", "polar_table_5_3_1_2_1_inverted.txt"), "inverted reliability table (index value)")
	flag.IntVar(&kbytes, "K", 512, "info bytes per packet")
	flag.Parse()

	data, err := os.ReadFile(inPath)
	if err != nil {
		panic(err)
	}
	bp, err := fec.NewBytePolarParamsFromInverted(table, "cache", 1024, kbytes)
	if err != nil {
		panic(err)
	}
	// encode each 1024-byte packet from Kbytes source (take first Kbytes of each 1024 chunk)
	packets := chunk(data, kbytes)
	// encode to codewords 1024 bytes each
	encPkts := make([][]byte, len(packets))
	tEnc := time.Now()
	for i := range packets {
		cw, err := fec.BytePolarEncodeSystematic(bp, packets[i])
		if err != nil {
			panic(err)
		}
		encPkts[i] = cw
	}
	encDur := time.Since(tEnc)

	// interleave in groups of L
	rng := rand.New(rand.NewSource(seed))
	var outGroups [][][]byte
	var groupPerms [][]int // for random interleaver per-group
	tInter := time.Now()
	for i := 0; i < len(encPkts); i += L {
		end := i + L
		if end > len(encPkts) {
			end = len(encPkts)
		}
		group := make([][]byte, end-i)
		copy(group, encPkts[i:end])
		// pad to L with zeros to simplify decoder logic
		if len(group) < L {
			pad := make([][]byte, L)
			copy(pad, group)
			for j := len(group); j < L; j++ {
				pad[j] = make([]byte, 1024)
			}
			group = pad
		}
		var interleaved [][]byte
		if inter == "random" {
			perm := rng.Perm(1024)
			var err error
			interleaved, err = fec.ByteRandomInterleave(group, perm)
			if err != nil {
				panic(err)
			}
			groupPerms = append(groupPerms, perm)
		} else {
			sp, err := fec.NewSlopeParams(1024, L, 0, 0)
			if err != nil {
				panic(err)
			}
			interleaved, err = fec.SlopeInterleave(group, 1024, sp)
			if err != nil {
				panic(err)
			}
		}
		outGroups = append(outGroups, interleaved)
	}
	interDur := time.Since(tInter)

	// apply losses and deinterleave + decode
	decoded := make([]byte, 0, len(data))
	tDec := time.Now()
	totalPkts := 0
	okPkts := 0
	for gi, grp := range outGroups {
		// losses
		recv := make([][]byte, len(grp))
		for l := 0; l < len(grp); l++ {
			if rng.Float64() < lossP {
				recv[l] = nil
			} else {
				recv[l] = grp[l]
			}
		}
		// deinterleave known -> reconstructed codewords and masks per original packet
		var de [][]byte
		var masks [][]bool
		var err error
		if inter == "random" {
			perm := groupPerms[gi]
			de, masks, err = fec.ByteRandomDeinterleaveKnown(recv, perm)
			if err != nil {
				panic(err)
			}
		} else {
			sp, _ := fec.NewSlopeParams(1024, L, 0, 0)
			de, masks, err = fec.SlopeDeinterleaveKnown(recv, 1024, sp)
			if err != nil {
				panic(err)
			}
		}
		// decode each packet (only first len(packets)%L possibly partial in last group)
		for s := 0; s < L; s++ {
			if len(decoded) >= len(data) {
				break
			}
			// Fast path: systematic + all present => direct recover
			all := true
			for i := 0; i < 1024; i++ {
				if !masks[s][i] {
					all = false
					break
				}
			}
			var src []byte
			var ok bool
			if all {
				src, err = fec.BytePolarFastRecover(bp, de[s])
				ok = true
			} else {
				src, ok, err = fec.BytePolarDecodeSystematic(bp, de[s], masks[s])
			}
			if err != nil {
				panic(err)
			}
			if !ok {
				// append zeros on failure to keep output length; in full tests we'd record failure
				decoded = append(decoded, make([]byte, kbytes)...)
			} else {
				decoded = append(decoded, src...)
				okPkts++
			}
			totalPkts++
		}
	}
	decDur := time.Since(tDec)

	if len(decoded) > len(data) {
		decoded = decoded[:len(data)]
	}
	if err := os.WriteFile(outPath, decoded, 0o644); err != nil {
		panic(err)
	}
	totalDur := encDur + interDur + decDur
	okRate := float64(okPkts) / float64(max(1, totalPkts))
	fmt.Printf("Byte-Polar: inter=%s L=%d p=%.2f | packets=%d ok=%d ok_rate=%.2f | t_enc=%v t_inter=%v t_dec=%v total=%v\n",
		inter, L, lossP, totalPkts, okPkts, okRate, encDur, interDur, decDur, totalDur)
	// Append CSV (updated header with systematic)
	_ = os.MkdirAll("results", 0o755)
	f, err := os.OpenFile(filepath.Join("results", "run_summary.csv"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err == nil {
		defer f.Close()
		// date, systematic, interleaver, L, loss_rate, N, K, packets, ok, ok_rate, t_encode_ms, t_interleave_ms, t_decode_ms, t_total_ms, throughput_MBps
		bytesMB := float64(len(data)) / (1024.0 * 1024.0)
		ms := func(d time.Duration) float64 { return float64(d.Milliseconds()) }
		thr := 0.0
		if totalDur > 0 {
			thr = bytesMB / (float64(totalDur) / float64(time.Second))
		}
		fmt.Fprintf(f, "%s,%t,%s,%d,%.4f,%d,%d,%d,%d,%.4f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
			time.Now().Format(time.RFC3339), true, inter, L, lossP, 1024, kbytes, totalPkts, okPkts,
			float64(okPkts)/float64(max(1, totalPkts)), ms(encDur), ms(interDur), ms(decDur), ms(totalDur), thr)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
