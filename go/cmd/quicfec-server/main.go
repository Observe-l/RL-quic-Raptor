package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"runtime/pprof"
	"time"

	"github.com/quic-go/quic-go/fecquic"
)

func main() {
	var (
		addr      = flag.String("addr", ":4444", "listen address")
		alpn      = flag.String("alpn", "quic-fec", "ALPN protocol")
		out       = flag.String("out", ".", "output directory")
		limit     = flag.Duration("timeout", 120*time.Second, "server timeout")
		rxBudget  = flag.Int("rx-budget-bytes", 10*1024*1024, "receiver buffer budget in bytes")
		rxDDL     = flag.Duration("rx-ddl", 50*time.Millisecond, "receiver decode deadline per block")
		rxWorkers = flag.Int("rx-workers", 2, "receiver decode workers")
		rxRing    = flag.Int("rx-ingress-ring", 4096, "receiver ingress ring size (power of two)")
		cpuProf   = flag.String("cpuprofile", "", "write CPU profile to file (optional)")
		memProf   = flag.String("memprofile", "", "write mem profile to file on exit (optional)")
	)
	flag.Parse()
	var cpuFile *os.File
	if *cpuProf != "" {
		var err error
		cpuFile, err = os.Create(*cpuProf)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cpuprofile error:", err)
			os.Exit(1)
		}
		_ = pprof.StartCPUProfile(cpuFile)
		defer pprof.StopCPUProfile()
		defer cpuFile.Close()
	}
	tlsConf, err := fecquic.GenerateServerTLSConfig(*alpn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	rx := fecquic.RXOptions{BudgetBytes: *rxBudget, DDL: *rxDDL, Workers: *rxWorkers, IngressRing: *rxRing}
	err = fecquic.ListenAndServeLoopWithRX(ctx, *addr, *alpn, *out, tlsConf, rx, func(p string) { fmt.Println("stored:", p) })
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "serve error:", err)
		os.Exit(1)
	}
	if *memProf != "" {
		f, err := os.Create(*memProf)
		if err == nil {
			_ = pprof.WriteHeapProfile(f)
			_ = f.Close()
		}
	}
}
