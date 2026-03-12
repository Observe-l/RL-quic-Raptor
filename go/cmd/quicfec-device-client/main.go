package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/quic-go/quic-go/fecquic"
)

func parseFlexibleDuration(value string) (time.Duration, error) {
	v := strings.TrimSpace(value)
	if v == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if !strings.ContainsAny(v, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		seconds, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, err
		}
		return time.Duration(seconds * float64(time.Second)), nil
	}
	return time.ParseDuration(v)
}

func main() {
	var (
		serverIP   = flag.String("server", "127.0.0.1", "server IP or hostname")
		serverPort = flag.Int("port", 25569, "server UDP port")
		alpn       = flag.String("alpn", "quic-fec", "ALPN protocol")
		filePath   = flag.String("in", "data/send.bin", "input file to send")
		insecure   = flag.Bool("insecure", true, "skip TLS verification")
		timeout    = flag.String("timeout", "60s", "client timeout; bare numbers mean seconds")
		connectTO  = flag.String("connect-timeout", "3s", "max time allowed for dialing + QUIC handshake; bare numbers mean seconds (0=use -timeout)")

		K      = flag.Int("K", 26, "source symbols K")
		R0     = flag.Int("R0", 6, "initial repair symbols R0 (N=K+R0)")
		Rstep  = flag.Int("Rstep", 4, "ARQ minimum append per NACK")
		ddlMS  = flag.Int("ddl-ms", 25, "receiver ARQ soft deadline (sent to server via header)")
		L      = flag.Int("L", 1200, "symbol bytes L")
		W      = flag.Int("W", 8, "ARQ window W (unfinished clusters)")
		maxAtt = flag.Int("max-attempts", 0, "ARQ max attempts per cluster (0=unlimited)")
		ackEvery = flag.Int("ack-every", 8, "write 1B on a stream every N datagrams (0=disable)")
		postWait = flag.String("post-wait", "0s", "linger after sending; bare numbers mean seconds")
		transport = flag.String("transport", "dgram", "symbol transport: dgram|stream")
		dgramWarn = flag.Int("dgram-warn", 1400, "warn if datagram exceeds bytes (0=off)")

		devRetx   = flag.Bool("dev-retx", true, "enable QUIC retransmission reason logging (requires build tag quicfecdev)")
		quicStats = flag.Bool("quic-stats", false, "enable QUIC-layer aggregate stats line")
	)
	flag.Parse()

	timeoutDur, err := parseFlexibleDuration(*timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad -timeout:", err)
		os.Exit(2)
	}
	connectTODur, err := parseFlexibleDuration(*connectTO)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad -connect-timeout:", err)
		os.Exit(2)
	}
	postWaitDur, err := parseFlexibleDuration(*postWait)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad -post-wait:", err)
		os.Exit(2)
	}

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
	if *ddlMS < 0 {
		fmt.Fprintln(os.Stderr, "bad -ddl-ms")
		os.Exit(2)
	}
	if *ackEvery < 0 {
		fmt.Fprintln(os.Stderr, "bad -ack-every")
		os.Exit(2)
	}
	if *transport != "dgram" && *transport != "stream" {
		fmt.Fprintln(os.Stderr, "bad -transport")
		os.Exit(2)
	}

	addr := net.JoinHostPort(*serverIP, strconv.Itoa(*serverPort))

	ctx, cancel := context.WithTimeout(context.Background(), timeoutDur)
	defer cancel()
	if connectTODur > 0 && connectTODur > timeoutDur {
		connectTODur = timeoutDur
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
		RxDDL:          time.Duration(*ddlMS) * time.Millisecond,
		PostWait:       postWaitDur,
		AckEvery:       *ackEvery,
		WarnDgramSize:  *dgramWarn,
		DialTimeout:    connectTODur,
		Transport:      *transport,
	}

	if err := fecquic.ClientSendFile(ctx, addr, *alpn, *filePath, opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
