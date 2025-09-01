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
		addr  = flag.String("addr", ":4444", "listen address")
		alpn  = flag.String("alpn", "quic-fec", "ALPN protocol")
		out   = flag.String("out", ".", "output directory")
		limit = flag.Duration("timeout", 120*time.Second, "server timeout")
	)
	flag.Parse()
	tlsConf, err := fecquic.GenerateServerTLSConfig(*alpn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	err = fecquic.ListenAndServeLoop(ctx, *addr, *alpn, *out, tlsConf, func(p string) { fmt.Println("stored:", p) })
	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		fmt.Fprintln(os.Stderr, "serve error:", err)
		os.Exit(1)
	}
}
