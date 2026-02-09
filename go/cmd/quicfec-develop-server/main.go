package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/quic-go/quic-go/fecquic"
)

func main() {
	var (
		addr      = flag.String("addr", ":4444", "listen address")
		alpn      = flag.String("alpn", "quic-fec", "ALPN protocol")
		out       = flag.String("out", ".", "output directory")
		limit     = flag.Duration("timeout", 120*time.Second, "server timeout")
		rxBudget  = flag.Int("rx-budget-bytes", 64*1024*1024, "receiver buffer budget in bytes")
		decodeDDL = flag.Duration("decode-ddl", 25*time.Millisecond, "receiver decode/check pacing (DECODE_DDL)")
		_         = flag.Duration("rx-ddl", 25*time.Millisecond, "DEPRECATED: use -decode-ddl")
		rxWorkers = flag.Int("rx-workers", 2, "receiver decode workers")

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

	tlsConf, err := fecquic.GenerateServerTLSConfig(*alpn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	rx := fecquic.RXOptions{BudgetBytes: *rxBudget, DecodeDDL: *decodeDDL, Workers: *rxWorkers}
	err = fecquic.ListenAndServeLoopWithRX(ctx, *addr, *alpn, *out, tlsConf, rx, func(p string) { fmt.Println("stored:", p) })
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "serve error:", err)
		os.Exit(1)
	}
}
