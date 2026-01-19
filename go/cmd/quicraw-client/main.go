package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	var (
		addr     = flag.String("addr", "127.0.0.1:4445", "server address")
		alpn     = flag.String("alpn", "quic-raw", "ALPN protocol")
		filePath = flag.String("file", "go/test_data/train_FD001.txt", "file to send")
		timeout  = flag.Duration("timeout", 60*time.Second, "client timeout")
		postWait = flag.Duration("post-wait", 0, "linger after sending")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{*alpn}}

	conn, err := quic.DialAddr(ctx, *addr, tlsConf, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial error:", err)
		os.Exit(1)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open stream error:", err)
		os.Exit(1)
	}
	defer func() { _ = stream.Close() }()

	f, err := os.Open(*filePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open file error:", err)
		os.Exit(1)
	}
	defer f.Close()

	base := filepath.Base(*filePath)
	if len(base) > 0xFFFF {
		fmt.Fprintln(os.Stderr, "filename too long")
		os.Exit(1)
	}
	if err := binary.Write(stream, binary.BigEndian, uint16(len(base))); err != nil {
		fmt.Fprintln(os.Stderr, "write nameLen error:", err)
		os.Exit(1)
	}
	if _, err := stream.Write([]byte(base)); err != nil {
		fmt.Fprintln(os.Stderr, "write name error:", err)
		os.Exit(1)
	}

	start := time.Now()
	n, err := io.CopyBuffer(stream, f, make([]byte, 256*1024))
	if err != nil {
		fmt.Fprintln(os.Stderr, "copy error:", err)
		os.Exit(1)
	}
	_ = stream.Close()
	// Wait for server completion ACK (1 byte).
	ack := []byte{0}
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.ReadFull(stream, ack); err != nil {
		fmt.Fprintln(os.Stderr, "read ack error:", err)
		os.Exit(1)
	}
	if *postWait > 0 {
		t := time.NewTimer(*postWait)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
	}
	_ = conn.CloseWithError(0, "")

	dur := time.Since(start)
	mbps := (float64(n) * 8 / 1e6) / dur.Seconds()
	fmt.Fprintf(os.Stderr, "[raw-client] sent=%s bytes=%d dur_ms=%d goodput_mbps=%.3f\n", base, n, dur.Milliseconds(), mbps)
}
