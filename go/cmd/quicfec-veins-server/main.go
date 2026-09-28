package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/quic-go/quic-go/fecquic"
	"github.com/quic-go/quic-go/veinscosim"
)

func main() {
	var (
		bridge    = flag.Int("bridge-port", 39999, "local RSU bridge UDP port")
		out       = flag.String("out", ".", "received-file directory")
		limit     = flag.Duration("timeout", 360*time.Second, "server lifetime")
		rxBudget  = flag.Int("rx-budget-bytes", 64*1024*1024, "receiver buffer budget")
		decodeDDL = flag.Duration("decode-ddl", 25*time.Millisecond, "decode/check pacing")
		rxWorkers = flag.Int("rx-workers", 2, "decode workers")
	)
	flag.Parse()
	pc, err := veinscosim.ListenServer(*bridge)
	if err != nil {
		fatal("bridge: %v", err)
	}
	defer pc.Close()
	tlsConf, err := fecquic.GenerateServerTLSConfig("quic-fec")
	if err != nil {
		fatal("TLS: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	rx := fecquic.RXOptions{
		BudgetBytes: *rxBudget, DecodeDDL: *decodeDDL, Workers: *rxWorkers,
		PacketConn: pc,
	}
	if err := fecquic.ListenAndServeLoopWithRX(ctx, ":4444", "quic-fec", *out, tlsConf, rx,
		func(path string) { fmt.Println("stored:", path) }); err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		fatal("serve: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
