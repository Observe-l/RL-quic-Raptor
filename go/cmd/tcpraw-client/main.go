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
		addr         = flag.String("addr", "127.0.0.1:45302", "server address")
		filePath     = flag.String("file", "go/test_data/train_FD001.txt", "file to send")
		timeout      = flag.Duration("timeout", 60*time.Second, "client timeout")
		measureDelay = flag.Bool("measure-delay", true, "send framed records for delay measurement")
		packetBytes  = flag.Int("packet-bytes", 1200, "payload bytes per record")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial error:", err)
		os.Exit(1)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(*timeout))

	f, err := os.Open(*filePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open file error:", err)
		os.Exit(1)
	}
	defer f.Close()

	bw := bufio.NewWriterSize(conn, 256*1024)
	br := bufio.NewReaderSize(conn, 64*1024)

	base := filepath.Base(*filePath)
	if len(base) > 0xFFFF {
		fmt.Fprintln(os.Stderr, "filename too long")
		os.Exit(1)
	}
	if err := binary.Write(bw, binary.BigEndian, uint16(len(base))); err != nil {
		fmt.Fprintln(os.Stderr, "write nameLen error:", err)
		os.Exit(1)
	}
	if _, err := bw.WriteString(base); err != nil {
		fmt.Fprintln(os.Stderr, "write name error:", err)
		os.Exit(1)
	}

	mode := byte(0)
	if *measureDelay {
		mode = 1
	}
	if err := bw.WriteByte(mode); err != nil {
		fmt.Fprintln(os.Stderr, "write mode error:", err)
		os.Exit(1)
	}

	start := time.Now()
	var n int64
	if !*measureDelay {
		n, err = io.CopyBuffer(bw, f, make([]byte, 256*1024))
		if err != nil {
			fmt.Fprintln(os.Stderr, "copy error:", err)
			os.Exit(1)
		}
		if err := bw.Flush(); err != nil {
			fmt.Fprintln(os.Stderr, "flush error:", err)
			os.Exit(1)
		}
	} else {
		payloadLen := *packetBytes
		if payloadLen <= 0 {
			payloadLen = 1200
		}
		buf := make([]byte, payloadLen)
		seq := uint64(0)
		for {
			r, rerr := f.Read(buf)
			if r > 0 {
				seq++
				sendNs := time.Now().UnixNano()
				if err := binary.Write(bw, binary.BigEndian, uint32(r)); err != nil {
					fmt.Fprintln(os.Stderr, "write len error:", err)
					os.Exit(1)
				}
				if err := binary.Write(bw, binary.BigEndian, seq); err != nil {
					fmt.Fprintln(os.Stderr, "write seq error:", err)
					os.Exit(1)
				}
				if err := binary.Write(bw, binary.BigEndian, int64(sendNs)); err != nil {
					fmt.Fprintln(os.Stderr, "write ts error:", err)
					os.Exit(1)
				}
				if _, err := bw.Write(buf[:r]); err != nil {
					fmt.Fprintln(os.Stderr, "write payload error:", err)
					os.Exit(1)
				}
				n += int64(r)
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				fmt.Fprintln(os.Stderr, "read file error:", rerr)
				os.Exit(1)
			}
		}
		// EOF marker
		if err := binary.Write(bw, binary.BigEndian, uint32(0)); err != nil {
			fmt.Fprintln(os.Stderr, "write eof marker error:", err)
			os.Exit(1)
		}
		if err := bw.Flush(); err != nil {
			fmt.Fprintln(os.Stderr, "flush error:", err)
			os.Exit(1)
		}
	}

	// Expect 1-byte ack.
	ack := []byte{0}
	if _, err := io.ReadFull(br, ack); err != nil {
		fmt.Fprintln(os.Stderr, "read ack error:", err)
		os.Exit(1)
	}

	dur := time.Since(start)
	mbps := (float64(n) * 8 / 1e6) / dur.Seconds()
	fmt.Fprintf(os.Stderr, "[tcpraw-client] sent=%s bytes=%d dur_ms=%d goodput_mbps=%.3f\n", base, n, dur.Milliseconds(), mbps)
}
