package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/quic-go/quic-go/fecquic"
)

func main() {
	var (
		serverIP   = flag.String("server", "127.0.0.1", "server IP or hostname")
		serverPort = flag.Int("port", 25569, "server UDP port")
		alpn       = flag.String("alpn", "quic-fec", "ALPN protocol")
		filePath   = flag.String("in", "data/send.bin", "input file to send")
		insecure   = flag.Bool("insecure", true, "skip TLS verification")
		timeout    = flag.Duration("timeout", 60*time.Second, "client timeout (overall)")
		connectTO  = flag.Duration("connect-timeout", 3*time.Second, "max time allowed for dialing + QUIC handshake (0=use -timeout)")

		K      = flag.Int("K", 26, "source symbols K")
		R0     = flag.Int("R0", 6, "initial repair symbols R0 (N=K+R0)")
		Rstep  = flag.Int("Rstep", 4, "ARQ minimum append per NACK")
		L      = flag.Int("L", 1200, "symbol bytes L")
		W      = flag.Int("W", 8, "ARQ window W (unfinished clusters)")
		maxAtt = flag.Int("max-attempts", 5, "ARQ max attempts per cluster")

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

	if *serverPort <= 0 || *serverPort > 65535 {
		fmt.Fprintln(os.Stderr, "bad -port")
		os.Exit(2)
	}
	if *K <= 0 {
		fmt.Fprintln(os.Stderr, "bad -K")
		os.Exit(2)
	}
	if *R0 < 0 {
		fmt.Fprintln(os.Stderr, "bad -R0 (must be >= 0)")
		os.Exit(2)
	}
	if *L <= 0 {
		fmt.Fprintln(os.Stderr, "bad -L")
		os.Exit(2)
	}
	addr := net.JoinHostPort(*serverIP, strconv.Itoa(*serverPort))

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *connectTO > 0 && *connectTO > *timeout {
		*connectTO = *timeout
	}

	n := *K + *R0
	opts := fecquic.SendOptions{
		K:              *K,
		N:              n,
		L:              *L,
		InsecureTLS:    *insecure,
		UseARQ:         true,
		InitialRepairs: *R0,
		WindowW:        *W,
		RStep:          *Rstep,
		MaxAttempts:    *maxAtt,
		DialTimeout:    *connectTO,
		Transport:      "dgram",
	}

	if err := fecquic.ClientSendFile(ctx, addr, *alpn, *filePath, opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
