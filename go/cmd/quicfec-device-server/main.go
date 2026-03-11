package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go/fecquic"
)

func main() {
	var (
		addr      = flag.String("addr", "0.0.0.0:25569", "listen address")
		alpn      = flag.String("alpn", "quic-fec", "ALPN protocol")
		outPath   = flag.String("out", "data/receive.bin", "output file path")
		timeout   = flag.Duration("timeout", 0, "server timeout (0=no timeout)")
		rxBudget  = flag.Int("rx-budget-bytes", 64*1024*1024, "receiver buffer budget in bytes")
		decodeDDL = flag.Duration("decode-ddl", 25*time.Millisecond, "receiver decode/check pacing (DECODE_DDL)")
		rxWorkers = flag.Int("rx-workers", 2, "receiver decode workers")
		enObs     = flag.Bool("enable-obs", false, "emit [rl-observation] JSON line")

		devRetx   = flag.Bool("dev-retx", true, "enable QUIC retransmission reason logging (requires build tag quicfecdev)")
		quicStats = flag.Bool("quic-stats", false, "enable QUIC-layer aggregate stats line")
	)
	flag.Parse()

	if *devRetx {
		_ = os.Setenv("QUIC_FEC_DEV_RETX", "1")
	}
	if *quicStats {
		_ = os.Setenv("QUIC_FEC_STATS", "1")
	}
	if os.Getenv("QUIC_FEC_CC_ALGO") == "" {
		_ = os.Setenv("QUIC_FEC_CC_ALGO", "bbrv2")
	}

	if err := fecquic.ResolveUDPAddr(*addr); err != nil {
		fmt.Fprintln(os.Stderr, "bad -addr:", err)
		os.Exit(2)
	}
	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "bad -out: empty")
		os.Exit(2)
	}

	tlsConf, err := fecquic.GenerateServerTLSConfig(*alpn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}

	ctx := context.Background()
	cancel := func() {}
	if *timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, *timeout)
	}
	defer cancel()

	absOut, _ := filepath.Abs(*outPath)
	fmt.Fprintln(os.Stderr, "[device-server] listen=", *addr, "out=", absOut)

	rx := fecquic.RXOptions{
		BudgetBytes:        *rxBudget,
		DecodeDDL:          *decodeDDL,
		Workers:            *rxWorkers,
		OutPath:            *outPath,
		DisableObservation: !*enObs,
	}

	outDir := filepath.Dir(*outPath)
	err = fecquic.ListenAndServeLoopWithRX(ctx, *addr, *alpn, outDir, tlsConf, rx, func(p string) {
		fmt.Println("stored:", p)
	})
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "serve error:", err)
		os.Exit(1)
	}
}
