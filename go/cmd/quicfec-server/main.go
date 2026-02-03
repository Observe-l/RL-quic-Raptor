package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quic-go/quic-go/fecquic"
)

func main() {
	// Default congestion control: enable CC and select BBRv2 unless the caller overrides.
	if strings.TrimSpace(os.Getenv("QUIC_FEC_CC_BYPASS")) == "" {
		_ = os.Setenv("QUIC_FEC_CC_BYPASS", "0")
	}
	if strings.TrimSpace(os.Getenv("QUIC_FEC_CC_ALGO")) == "" {
		_ = os.Setenv("QUIC_FEC_CC_ALGO", "bbrv2")
	}

	var (
		addr      = flag.String("addr", ":4444", "listen address")
		alpn      = flag.String("alpn", "quic-fec", "ALPN protocol")
		out       = flag.String("out", ".", "output directory")
		limit     = flag.Duration("timeout", 120*time.Second, "server timeout")
		rxBudget  = flag.Int("rx-budget-bytes", 64*1024*1024, "receiver buffer budget in bytes")
		rxWorkers = flag.Int("rx-workers", 2, "receiver decode workers")
	)
	flag.Parse()
	tlsConf, err := fecquic.GenerateServerTLSConfig(*alpn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	rx := fecquic.RXOptions{BudgetBytes: *rxBudget, Workers: *rxWorkers}
	err = fecquic.ListenAndServeLoopWithRX(ctx, *addr, *alpn, *out, tlsConf, rx, func(p string) { fmt.Println("stored:", p) })
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "serve error:", err)
		os.Exit(1)
	}
}
