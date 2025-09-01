package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/csv"
	"flag"
	"fmt"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/quic-go/quic-go/fec"
)

type resultAgg struct {
	okCount  int
	trials   int
	encTotal time.Duration
	decTotal time.Duration
}

func main() {
	exp := flag.String("exp", "A", "Experiment to run: A or B")
	N := flag.Int("N", 32, "total symbols per generation")
	K := flag.Int("K", 26, "source symbols per generation")
	L := flag.Int("L", 1500, "bytes per symbol")
	repeats := flag.Int("repeats", 200, "repeats for Experiment A")
	objMB := flag.Int("objMB", 3, "object size in MB for Experiment B")
	pList := flag.String("p", "0,0.001,0.005,0.01,0.05,0.10,0.15", "comma-separated loss probabilities for Experiment B")
	trials := flag.Int("trials", 10000, "trials per p for Experiment B")
	seed := flag.Int64("seed", 1337, "PRNG seed for loss generation")
	schemes := flag.String("schemes", "raptorq,rs,rlc,polar", "comma-separated list of schemes to run")
	csvPath := flag.String("csv", "", "optional CSV output path")
	dataPath := flag.String("data", filepath.Join("test_data", "train_FD001.txt"), "path to data file for Experiment A")
	flag.Parse()

	switch strings.ToUpper(*exp) {
	case "A":
		runExperimentA(*dataPath, *K, *L, *repeats)
	case "B":
		ps := parsePList(*pList)
		runExperimentB(*schemes, *N, *K, *L, *objMB, ps, *trials, *seed, *csvPath)
	default:
		fmt.Println("unknown exp; use A or B")
	}
}

func parsePList(s string) []float64 {
	parts := strings.Split(s, ",")
	out := make([]float64, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		var v float64
		fmt.Sscanf(p, "%f", &v)
		out = append(out, v)
	}
	return out
}

func runExperimentA(path string, K, L, repeats int) {
	src, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("read %s: %v\n", path, err)
		os.Exit(1)
	}
	encSum, decSum := time.Duration(0), time.Duration(0)
	for rep := 0; rep < repeats; rep++ {
		off := 0
		out := make([]byte, 0, len(src))
		for off < len(src) {
			end := off + K*L
			if end > len(src) {
				end = len(src)
			}
			chunk := make([]byte, end-off)
			copy(chunk, src[off:end])
			off = end

			t0 := time.Now()
			enc, err := fec.NewRaptorQEncoder(chunk, K, L)
			if err != nil {
				fmt.Println("encoder:", err)
				os.Exit(1)
			}
			encSum += time.Since(t0)
			dec, err := fec.NewRaptorQDecoder(len(chunk), L)
			if err != nil {
				fmt.Println("decoder:", err)
				os.Exit(1)
			}
			for i := 0; i < K; i++ {
				if _, err := dec.AddSymbol(uint32(i), enc.GenSymbol(uint32(i))); err != nil {
					fmt.Println("add:", err)
					os.Exit(1)
				}
			}
			t1 := time.Now()
			ok, got, err := dec.Decode()
			if err != nil || !ok {
				fmt.Println("decode fail:", err)
				os.Exit(1)
			}
			decSum += time.Since(t1)
			out = append(out, got...)
		}
		if len(out) != len(src) || !bytesEqual(out, src) {
			fmt.Printf("mismatch at rep %d\n", rep)
			os.Exit(1)
		}
	}
	fmt.Printf("Experiment A: RaptorQ p=0 enc(total)=%v dec(total)=%v (repeats=%d)\n", encSum, decSum, repeats)
}

func runExperimentB(schemes string, N, K, L, objMB int, ps []float64, trials int, seed int64, csvPath string) {
	obj := make([]byte, objMB<<20)
	if _, err := crand.Read(obj); err != nil {
		fmt.Println("rand:", err)
		os.Exit(1)
	}
	rng := mrand.New(mrand.NewSource(seed))
	list := strings.Split(schemes, ",")

	var csvw *csv.Writer
	var f *os.File
	if csvPath != "" {
		var err error
		f, err = os.OpenFile(csvPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			fmt.Println("csv open:", err)
			os.Exit(1)
		}
		csvw = csv.NewWriter(bufio.NewWriter(f))
		// header if file empty
		fi, _ := f.Stat()
		if fi.Size() == 0 {
			_ = csvw.Write([]string{"scheme", "p", "trials", "ok_rate", "sum_encode_ms", "avg_encode_ms", "sum_decode_ms", "avg_decode_ms", "N", "K", "L", "seed"})
			csvw.Flush()
		}
	}

	for _, scheme := range list {
		scheme = strings.TrimSpace(scheme)
		if scheme == "" {
			continue
		}
		for _, p := range ps {
			agg := runTrialsOneScheme(scheme, N, K, L, obj, p, trials, rng)
			rate := float64(agg.okCount) / float64(agg.trials)
			encMS := float64(agg.encTotal.Microseconds()) / 1000.0
			decMS := float64(agg.decTotal.Microseconds()) / 1000.0
			avgEnc := encMS / float64(trials)
			avgDec := decMS / float64(trials)
			fmt.Printf("scheme=%s p=%.4f ok=%.4f enc(total)=%.1fms dec(total)=%.1fms\n", scheme, p, rate, encMS, decMS)
			if csvw != nil {
				_ = csvw.Write([]string{
					scheme,
					fmt.Sprintf("%.6f", p),
					fmt.Sprintf("%d", trials),
					fmt.Sprintf("%.6f", rate),
					fmt.Sprintf("%.3f", encMS),
					fmt.Sprintf("%.6f", avgEnc),
					fmt.Sprintf("%.3f", decMS),
					fmt.Sprintf("%.6f", avgDec),
					fmt.Sprintf("%d", N), fmt.Sprintf("%d", K), fmt.Sprintf("%d", L),
					fmt.Sprintf("%d", seed),
				})
				csvw.Flush()
			}
		}
	}

	if f != nil {
		_ = f.Close()
	}
}

func runTrialsOneScheme(scheme string, N, K, L int, obj []byte, p float64, trials int, rng *mrand.Rand) resultAgg {
	agg := resultAgg{trials: trials}
	for t := 0; t < trials; t++ {
		off := 0
		out := make([]byte, 0, len(obj))
		okAll := true
		encTotalGen := time.Duration(0)
		decTotalGen := time.Duration(0)
		for off < len(obj) {
			end := off + K*L
			if end > len(obj) {
				end = len(obj)
			}
			data := obj[off:end]
			off = end
			switch scheme {
			case "raptorq":
				t0 := time.Now()
				enc, err := fec.NewRaptorQEncoder(data, K, L)
				if err != nil {
					okAll = false
					continue
				}
				encTotalGen += time.Since(t0)
				dec, err := fec.NewRaptorQDecoder(len(data), L)
				if err != nil {
					okAll = false
					continue
				}
				for i := 0; i < N; i++ {
					if rng.Float64() < p {
						continue
					}
					id := uint32(i)
					if _, err := dec.AddSymbol(id, enc.GenSymbol(id)); err != nil {
						okAll = false
						break
					}
				}
				t1 := time.Now()
				ok, got, err := dec.Decode()
				decTotalGen += time.Since(t1)
				if err != nil || !ok {
					okAll = false
					continue
				}
				out = append(out, got...)
			case "rs":
				src := make([][]byte, K)
				for i := 0; i < K; i++ {
					b := make([]byte, L)
					o := i * L
					if o < len(data) {
						e := o + L
						if e > len(data) {
							e = len(data)
						}
						copy(b, data[o:e])
					}
					src[i] = b
				}
				t0 := time.Now()
				par, err := fec.EncodeRS(src, K, N-K)
				if err != nil {
					okAll = false
					continue
				}
				encTotalGen += time.Since(t0)
				recv := make([]fec.Packet, 0, N)
				for i := 0; i < N; i++ {
					if rng.Float64() < p {
						continue
					}
					if i < K {
						recv = append(recv, fec.Packet{Index: i, Data: src[i]})
					} else {
						recv = append(recv, par[i-K])
					}
				}
				t1 := time.Now()
				dec, ok := fec.DecodeRS(recv, K, N-K)
				decTotalGen += time.Since(t1)
				if !ok {
					okAll = false
					continue
				}
				for i := 0; i < K; i++ {
					out = append(out, dec[i]...)
				}
			case "rlc":
				src := make([][]byte, K)
				for i := 0; i < K; i++ {
					b := make([]byte, L)
					o := i * L
					if o < len(data) {
						e := o + L
						if e > len(data) {
							e = len(data)
						}
						copy(b, data[o:e])
					}
					src[i] = b
				}
				t0 := time.Now()
				par := fec.EncodeRLC(src, K, N-K, "gf256")
				encTotalGen += time.Since(t0)
				recv := make([]fec.Packet, 0, N)
				for i := 0; i < N; i++ {
					if rng.Float64() < p {
						continue
					}
					if i < K {
						recv = append(recv, fec.Packet{Index: i, Data: src[i]})
					} else {
						recv = append(recv, par[i-K])
					}
				}
				t1 := time.Now()
				dec, ok := fec.DecodeRLC(recv, K, "gf256")
				decTotalGen += time.Since(t1)
				if !ok {
					okAll = false
					continue
				}
				for i := 0; i < K; i++ {
					out = append(out, dec[i]...)
				}
			case "polar":
				pp, err := fec.NewPacketPolarParams(N, K, 0.05, L)
				if err != nil {
					okAll = false
					continue
				}
				src := make([][]byte, K)
				for i := 0; i < K; i++ {
					b := make([]byte, L)
					o := i * L
					if o < len(data) {
						e := o + L
						if e > len(data) {
							e = len(data)
						}
						copy(b, data[o:e])
					}
					src[i] = b
				}
				t0 := time.Now()
				par := fec.PacketPolarEncode(pp, src)
				encTotalGen += time.Since(t0)
				recv := make([]fec.Packet, 0, N)
				for i := 0; i < N; i++ {
					if rng.Float64() < p {
						continue
					}
					if i < K {
						recv = append(recv, fec.Packet{Index: i, Data: src[i]})
					} else {
						recv = append(recv, fec.Packet{Index: i, Data: par[i-K]})
					}
				}
				t1 := time.Now()
				dec, ok := fec.PacketPolarDecode(pp, recv)
				decTotalGen += time.Since(t1)
				if !ok {
					okAll = false
					continue
				}
				for i := 0; i < K; i++ {
					out = append(out, dec[i]...)
				}
			default:
				okAll = false
			}
			// Do not break on failure: continue to process remaining generations
			// so that encode time remains independent of loss rate p.
		}
		if okAll {
			// clamp to original object size (defensive; out should match obj when okAll)
			if len(out) > len(obj) {
				out = out[:len(obj)]
			}
			// quick compare without importing bytes
			if bytesEqual(out, obj) {
				agg.okCount++
			}
		}
		agg.encTotal += encTotalGen
		agg.decTotal += decTotalGen
	}
	return agg
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
