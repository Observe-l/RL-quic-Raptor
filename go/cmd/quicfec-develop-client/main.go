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
		limit     = flag.Duration("timeout", 600*time.Second, "client timeout")
		insecure  = flag.Bool("insecure", true, "skip TLS verification")
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
		rxDDL     = flag.Duration("rx-ddl", 0, "receiver ARQ soft deadline (DDL_MS) in ms (sent to server via header; 0=unspecified)")
		R0        = flag.Int("R0", -1, "initial extra repairs (>=0 exact; -1=auto: N-K)")
		W         = flag.Int("W", 8, "ARQ window W (unfinished clusters)")
		Rstep     = flag.Int("Rstep", 4, "ARQ extra repairs appended per NACK (0 allowed; <0 uses default)")
		maxAtt    = flag.Int("max-attempts", 0, "ARQ max attempts per cluster (0=unlimited)")

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

	ctx, cancel := context.WithTimeout(context.Background(), *limit)
	defer cancel()
	opts := fecquic.SendOptions{K: *K, N: *N, L: *L, InsecureTLS: *insecure, DropProb: *loss, PaceEach: *pace, BlockPause: *blkPause, RxDDL: *rxDDL, WarnDgramSize: *warn, PostWait: *postWait, AckEvery: *ackEvery, Transport: *transport, UseARQ: *arq, InitialRepairs: *R0, WindowW: *W, RStep: *Rstep, MaxAttempts: *maxAtt}
	if err := fecquic.ClientSendFile(ctx, *addr, *alpn, *filePath, opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
