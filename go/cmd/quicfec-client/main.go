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
		addr      = flag.String("addr", "127.0.0.1:4444", "server address")
		alpn      = flag.String("alpn", "quic-fec", "ALPN protocol")
		filePath  = flag.String("file", "go/test_data/train_FD001.txt", "file to send")
		insecure  = flag.Bool("insecure", true, "skip TLS verification")
		timeout   = flag.Duration("timeout", 60*time.Second, "client timeout (overall)")
		connectTO = flag.Duration("connect-timeout", 3*time.Second, "max time allowed for dialing + QUIC handshake (0=use -timeout)")
		N         = flag.Int("N", 32, "block length N")
		K         = flag.Int("K", 26, "source symbols K")
		L         = flag.Int("L", 1200, "symbol bytes L")
		loss      = flag.Float64("loss", 0.0, "sender drop probability (simulate)")
		pace      = flag.Duration("pace", 0, "sleep between datagrams")
		blkPause  = flag.Duration("block-pause", 0, "sleep after each block")
		warn      = flag.Int("dgram-warn", 0, "warn if datagram exceeds bytes (0=off)")
		postWait  = flag.Duration("post-wait", 0, "linger after sending to allow server to finalize")
		ackEvery  = flag.Int("ack-every", 8, "write 1B on a stream every N datagrams (0=auto)")
		transport = flag.String("transport", "dgram", "symbol transport: dgram|stream")
		arq       = flag.Bool("arq", false, "enable ARQ control plane (NACK/ACK)")
		R0        = flag.Int("R0", -1, "initial extra repairs (>=0 exact; -1=auto: N-K)")
		W         = flag.Int("W", 8, "ARQ window W (unfinished clusters)")
		Rstep     = flag.Int("Rstep", 4, "extra repair symbols appended to each NACK response")
		maxAtt    = flag.Int("max-attempts", 5, "ARQ max attempts per cluster")
	)
	flag.Parse()
	if os.Getenv("QUIC_FEC_CC_ALGO") == "" {
		_ = os.Setenv("QUIC_FEC_CC_ALGO", "bbrv2")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	if *connectTO > 0 && *connectTO > *timeout {
		// Avoid making connect-timeout the effective total timeout.
		*connectTO = *timeout
	}
	opts := fecquic.SendOptions{K: *K, N: *N, L: *L, InsecureTLS: *insecure, DropProb: *loss, PaceEach: *pace, BlockPause: *blkPause, WarnDgramSize: *warn, PostWait: *postWait, AckEvery: *ackEvery, Transport: *transport, UseARQ: *arq, InitialRepairs: *R0, WindowW: *W, RStep: *Rstep, MaxAttempts: *maxAtt, DialTimeout: *connectTO}
	if err := fecquic.ClientSendFile(ctx, *addr, *alpn, *filePath, opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
