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

		mode, err := br.ReadByte()
		if err != nil {
			fmt.Fprintln(os.Stderr, "read mode error:", err)
			_ = stream.Close()
			_ = conn.CloseWithError(0, "")
			continue
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

		var n int64
		var delaySumMs float64
		var delayCnt int64
		if mode == 0 {
			n, err = io.CopyBuffer(f, br, make([]byte, 256*1024))
			_ = f.Close()
			if err != nil {
				fmt.Fprintln(os.Stderr, "copy error:", err)
				_ = stream.Close()
				_ = conn.CloseWithError(0, "")
				continue
			}
		} else {
			for {
				var plen uint32
				if err := binary.Read(br, binary.BigEndian, &plen); err != nil {
					if err == io.EOF {
						break
					}
					fmt.Fprintln(os.Stderr, "read len error:", err)
					_ = f.Close()
					_ = stream.Close()
					_ = conn.CloseWithError(0, "")
					continue
				}
				if plen == 0 {
					break
				}
				var seq uint64
				var sendNs int64
				if err := binary.Read(br, binary.BigEndian, &seq); err != nil {
					fmt.Fprintln(os.Stderr, "read seq error:", err)
					_ = f.Close()
					_ = stream.Close()
					_ = conn.CloseWithError(0, "")
					continue
				}
				if err := binary.Read(br, binary.BigEndian, &sendNs); err != nil {
					fmt.Fprintln(os.Stderr, "read ts error:", err)
					_ = f.Close()
					_ = stream.Close()
					_ = conn.CloseWithError(0, "")
					continue
				}
				buf := make([]byte, int(plen))
				if _, err := io.ReadFull(br, buf); err != nil {
					fmt.Fprintln(os.Stderr, "read payload error:", err)
					_ = f.Close()
					_ = stream.Close()
					_ = conn.CloseWithError(0, "")
					continue
				}
				recvNs := time.Now().UnixNano()
				dms := float64(recvNs-sendNs) / 1e6
				if dms >= 0 && dms < 60000 {
					delaySumMs += dms
					delayCnt++
				}
				wn, werr := f.Write(buf)
				n += int64(wn)
				if werr != nil {
					fmt.Fprintln(os.Stderr, "write file error:", werr)
					_ = f.Close()
					_ = stream.Close()
					_ = conn.CloseWithError(0, "")
					continue
				}
			}
			_ = f.Close()
			if delayCnt > 0 {
				avg := delaySumMs / float64(delayCnt)
				fmt.Fprintf(os.Stderr, "[delay] delay_ms_avg=%.3f delay_samples=%d\n", avg, delayCnt)
			}
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
