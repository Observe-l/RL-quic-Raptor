package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		addr      = flag.String("addr", "0.0.0.0:25569", "listen address")
		alpn      = flag.String("alpn", "quic-fec", "ALPN protocol")
		outPath   = flag.String("out", "data/receive.bin", "output file path")
		timeout   = flag.String("timeout", "0", "server timeout; bare numbers mean seconds, 0 means no timeout")
		rttMS     = flag.Int("rtt-ms", 0, "manual RTT override in ms for ARQ waiting (0=use measured SRTT)")
		rxBudget  = flag.Int("rx-budget-bytes", 64*1024*1024, "receiver buffer budget in bytes")
		decodeDDL = flag.String("decode-ddl", "25ms", "receiver decode/check pacing; bare numbers mean seconds")
		rxWorkers = flag.Int("rx-workers", 2, "receiver decode workers")
		enObs     = flag.Bool("enable-obs", false, "emit [rl-observation] JSON line")

		devRetx   = flag.Bool("dev-retx", true, "enable QUIC retransmission reason logging (requires build tag quicfecdev)")
		quicStats = flag.Bool("quic-stats", false, "enable QUIC-layer aggregate stats line")
	)
	flag.Parse()

	timeoutDur, err := parseFlexibleDuration(*timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad -timeout:", err)
		os.Exit(2)
	}
	decodeDDLDur, err := parseFlexibleDuration(*decodeDDL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad -decode-ddl:", err)
		os.Exit(2)
	}

	if *devRetx {
		_ = os.Setenv("QUIC_FEC_DEV_RETX", "1")
	}
	if *quicStats {
		_ = os.Setenv("QUIC_FEC_STATS", "1")
	}
	if *rttMS > 0 {
		_ = os.Setenv("QUIC_FEC_SERVER_RTT_MS", strconv.Itoa(*rttMS))
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
	if *rttMS < 0 {
		fmt.Fprintln(os.Stderr, "bad -rtt-ms")
		os.Exit(2)
	}

	tlsConf, err := fecquic.GenerateServerTLSConfig(*alpn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}

	ctx := context.Background()
	cancel := func() {}
	if timeoutDur > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeoutDur)
	}
	defer cancel()

	absOut, _ := filepath.Abs(*outPath)
	fmt.Fprintln(os.Stderr, "[device-server] listen=", *addr, "out=", absOut)

	rx := fecquic.RXOptions{
		BudgetBytes:        *rxBudget,
		DecodeDDL:          decodeDDLDur,
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
