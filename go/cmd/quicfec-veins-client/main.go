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
		addr      = flag.String("addr", "10.77.0.1:4444", "virtual RSU address")
		bridge    = flag.Int("bridge-port", 40000, "local Veins bridge UDP port")
		vehicleID = flag.Int("vehicle-id", 0, "SUMO/Veins vehicle index")
		alpn      = flag.String("alpn", "quic-fec", "ALPN protocol")
		filePath  = flag.String("file", "", "file to send")
		insecure  = flag.Bool("insecure", true, "skip TLS verification")
		timeout   = flag.Duration("timeout", 120*time.Second, "client timeout (overall)")
		connectTO = flag.Duration("connect-timeout", 30*time.Second, "max dialing + handshake time")
		N         = flag.Int("N", 32, "block length N")
		K         = flag.Int("K", 26, "source symbols K")
		L         = flag.Int("L", 1200, "symbol bytes L")
		loss      = flag.Float64("loss", 0, "sender-side drop probability")
		pace      = flag.Duration("pace", 0, "sleep between datagrams")
		blkPause  = flag.Duration("block-pause", 0, "sleep after each block")
		warn      = flag.Int("dgram-warn", 0, "warn above datagram size")
		postWait  = flag.Duration("post-wait", 0, "linger before closing")
		ackEvery  = flag.Int("ack-every", 8, "ack-eliciting stream write interval")
		transport = flag.String("transport", "dgram", "symbol transport: dgram|stream")
		arq       = flag.Bool("arq", true, "enable ARQ control plane")
		R0        = flag.Int("R0", 6, "initial repair symbols")
		W         = flag.Int("W", 8, "ARQ window")
		Rstep     = flag.Int("Rstep", 4, "repairs per NACK response")
		maxAtt    = flag.Int("max-attempts", 5, "maximum ARQ attempts per cluster")
	)
	flag.Parse()
	if *filePath == "" {
		fatal("-file is required")
	}
	if os.Getenv("QUIC_FEC_CC_ALGO") == "" {
		_ = os.Setenv("QUIC_FEC_CC_ALGO", "bbrv2")
	}
	pc, err := veinscosim.ListenClient(*vehicleID, *bridge)
	if err != nil {
		fatal("bridge: %v", err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	opts := fecquic.SendOptions{
		K: *K, N: *N, L: *L, InsecureTLS: *insecure, DropProb: *loss,
		PaceEach: *pace, BlockPause: *blkPause, WarnDgramSize: *warn,
		PostWait: *postWait, AckEvery: *ackEvery, Transport: *transport,
		UseARQ: *arq, InitialRepairs: *R0, WindowW: *W, RStep: *Rstep,
		MaxAttempts: *maxAtt, DialTimeout: *connectTO, PacketConn: pc,
	}
	if err := fecquic.ClientSendFile(ctx, *addr, *alpn, *filePath, opts); err != nil {
		fatal("send: %v", err)
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
