package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/fecquic"
)

func main() {
	var (
		addr     = flag.String("addr", ":4445", "listen address")
		alpn     = flag.String("alpn", "quic-raw", "ALPN protocol")
		outDir   = flag.String("out", ".", "output directory")
		timeout  = flag.Duration("timeout", 120*time.Second, "server timeout")
		fileSufx = flag.String("suffix", ".recv", "output file suffix")
	)
	flag.Parse()

	tlsConf, err := fecquic.GenerateServerTLSConfig(*alpn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls error:", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	listener, err := quic.ListenAddr(*addr, tlsConf, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen error:", err)
		os.Exit(1)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			// Normal shutdown paths.
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "accept conn error:", err)
			os.Exit(1)
		}

		start := time.Now()
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept stream error:", err)
			_ = conn.CloseWithError(0, "")
			continue
		}

		br := bufio.NewReaderSize(stream, 64*1024)
		var nameLen uint16
		if err := binary.Read(br, binary.BigEndian, &nameLen); err != nil {
			fmt.Fprintln(os.Stderr, "read nameLen error:", err)
			_ = stream.Close()
			_ = conn.CloseWithError(0, "")
			continue
		}
		nameBuf := make([]byte, int(nameLen))
		if _, err := io.ReadFull(br, nameBuf); err != nil {
			fmt.Fprintln(os.Stderr, "read name error:", err)
			_ = stream.Close()
			_ = conn.CloseWithError(0, "")
			continue
		}
		base := filepath.Base(string(nameBuf))
		if base == "." || base == string(os.PathSeparator) || base == "" {
			base = "recv"
		}

		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir error:", err)
			_ = stream.Close()
			_ = conn.CloseWithError(0, "")
			continue
		}
		outPath := filepath.Join(*outDir, base+*fileSufx)
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create error:", err)
			_ = stream.Close()
			_ = conn.CloseWithError(0, "")
			continue
		}

		n, err := io.CopyBuffer(f, br, make([]byte, 256*1024))
		_ = f.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "copy error:", err)
			_ = stream.Close()
			_ = conn.CloseWithError(0, "")
			continue
		}
		// Application-level ack so the client doesn't close the connection early.
		_, _ = stream.Write([]byte{1})
		_ = stream.Close()
		_ = conn.CloseWithError(0, "")

		dur := time.Since(start)
		mbps := (float64(n) * 8 / 1e6) / dur.Seconds()
		fmt.Fprintf(os.Stderr, "[raw-server] stored=%s bytes=%d dur_ms=%d goodput_mbps=%.3f\n", outPath, n, dur.Milliseconds(), mbps)
	}
}
