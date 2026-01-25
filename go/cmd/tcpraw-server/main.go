package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var (
		addr    = flag.String("addr", ":45302", "listen address")
		outDir  = flag.String("out", ".", "output directory")
		timeout = flag.Duration("timeout", 120*time.Second, "server timeout")
		suffix  = flag.String("suffix", ".recv_tcp", "output file suffix")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen error:", err)
		os.Exit(1)
	}
	defer ln.Close()

	_ = ln.(*net.TCPListener).SetDeadline(time.Now().Add(*timeout))

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return
			}
			if ctx.Err() != nil {
				return
			}
			fmt.Fprintln(os.Stderr, "accept error:", err)
			return
		}

		func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(*timeout))

			start := time.Now()
			br := bufio.NewReaderSize(conn, 64*1024)
			bw := bufio.NewWriterSize(conn, 64*1024)

			var nameLen uint16
			if err := binary.Read(br, binary.BigEndian, &nameLen); err != nil {
				fmt.Fprintln(os.Stderr, "read nameLen error:", err)
				return
			}
			nameBuf := make([]byte, int(nameLen))
			if _, err := io.ReadFull(br, nameBuf); err != nil {
				fmt.Fprintln(os.Stderr, "read name error:", err)
				return
			}
			base := filepath.Base(string(nameBuf))
			if base == "." || base == string(os.PathSeparator) || base == "" {
				base = "recv"
			}

			mode, err := br.ReadByte()
			if err != nil {
				fmt.Fprintln(os.Stderr, "read mode error:", err)
				return
			}

			if err := os.MkdirAll(*outDir, 0o755); err != nil {
				fmt.Fprintln(os.Stderr, "mkdir error:", err)
				return
			}
			outPath := filepath.Join(*outDir, base+*suffix)
			f, err := os.Create(outPath)
			if err != nil {
				fmt.Fprintln(os.Stderr, "create error:", err)
				return
			}
			defer f.Close()

			var n int64
			var delaySumMs float64
			var delayCnt int64

			if mode == 0 {
				n, err = io.CopyBuffer(f, br, make([]byte, 256*1024))
				if err != nil {
					fmt.Fprintln(os.Stderr, "copy error:", err)
					return
				}
			} else {
				for {
					var plen uint32
					if err := binary.Read(br, binary.BigEndian, &plen); err != nil {
						if err == io.EOF {
							break
						}
						fmt.Fprintln(os.Stderr, "read len error:", err)
						return
					}
					if plen == 0 {
						break
					}
					var seq uint64
					var sendNs int64
					if err := binary.Read(br, binary.BigEndian, &seq); err != nil {
						fmt.Fprintln(os.Stderr, "read seq error:", err)
						return
					}
					if err := binary.Read(br, binary.BigEndian, &sendNs); err != nil {
						fmt.Fprintln(os.Stderr, "read ts error:", err)
						return
					}
					buf := make([]byte, int(plen))
					if _, err := io.ReadFull(br, buf); err != nil {
						fmt.Fprintln(os.Stderr, "read payload error:", err)
						return
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
						return
					}
				}
			}

			_ = f.Sync()
			// App-level ack
			_, _ = bw.Write([]byte{1})
			_ = bw.Flush()

			dur := time.Since(start)
			mbps := (float64(n) * 8 / 1e6) / dur.Seconds()
			fmt.Fprintf(os.Stderr, "[tcpraw-server] stored=%s bytes=%d dur_ms=%d goodput_mbps=%.3f\n", outPath, n, dur.Milliseconds(), mbps)
			if delayCnt > 0 {
				avg := delaySumMs / float64(delayCnt)
				fmt.Fprintf(os.Stderr, "[delay] delay_ms_avg=%.3f delay_samples=%d\n", avg, delayCnt)
			}
		}()
	}
}
