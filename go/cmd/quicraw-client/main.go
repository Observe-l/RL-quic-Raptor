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
	"github.com/quic-go/quic-go/fecquic"
	"github.com/quic-go/quic-go/logging"
)

func main() {
	var (
		addr         = flag.String("addr", "127.0.0.1:4445", "server address")
		alpn         = flag.String("alpn", "quic-raw", "ALPN protocol")
		filePath     = flag.String("file", "go/test_data/train_FD001.txt", "file to send")
		timeout      = flag.Duration("timeout", 60*time.Second, "client timeout")
		postWait     = flag.Duration("post-wait", 0, "linger after sending")
		measureDelay = flag.Bool("measure-delay", true, "send framed records for delay measurement")
		packetBytes  = flag.Int("packet-bytes", 1200, "payload bytes per record")
	)
	flag.Parse()
	// Phase timing (client-side)
	startTotal := time.Now()
	var dialDur, openStreamDur, headerDur, sendDur, ackDur, postWaitDur time.Duration

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{*alpn}}

	qconf := &quic.Config{
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			return fecquic.NewCCDebugConnTracer()
		},
	}
	t0 := time.Now()
	conn, err := quic.DialAddr(ctx, *addr, tlsConf, qconf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial error:", err)
		os.Exit(1)
	}
	dialDur = time.Since(t0)
	defer func() { _ = conn.CloseWithError(0, "") }()

	t0 = time.Now()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open stream error:", err)
		os.Exit(1)
	}
	openStreamDur = time.Since(t0)
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
	t0 = time.Now()
	if err := binary.Write(stream, binary.BigEndian, uint16(len(base))); err != nil {
		fmt.Fprintln(os.Stderr, "write nameLen error:", err)
		os.Exit(1)
	}
	if _, err := stream.Write([]byte(base)); err != nil {
		fmt.Fprintln(os.Stderr, "write name error:", err)
		os.Exit(1)
	}
	mode := byte(0)
	if *measureDelay {
		mode = 1
	}
	if _, err := stream.Write([]byte{mode}); err != nil {
		fmt.Fprintln(os.Stderr, "write mode error:", err)
		os.Exit(1)
	}
	headerDur = time.Since(t0)

	start := time.Now()
	var n int64
	if !*measureDelay {
		tSend := time.Now()
		n, err = io.CopyBuffer(stream, f, make([]byte, 256*1024))
		if err != nil {
			fmt.Fprintln(os.Stderr, "copy error:", err)
			os.Exit(1)
		}
		sendDur = time.Since(tSend)
	} else {
		payloadLen := *packetBytes
		if payloadLen <= 0 {
			payloadLen = 1200
		}
		buf := make([]byte, payloadLen)
		seq := uint64(0)
		tSend := time.Now()
		for {
			r, rerr := f.Read(buf)
			if r > 0 {
				seq++
				sendNs := time.Now().UnixNano()
				if err := binary.Write(stream, binary.BigEndian, uint32(r)); err != nil {
					fmt.Fprintln(os.Stderr, "write len error:", err)
					os.Exit(1)
				}
				if err := binary.Write(stream, binary.BigEndian, seq); err != nil {
					fmt.Fprintln(os.Stderr, "write seq error:", err)
					os.Exit(1)
				}
				if err := binary.Write(stream, binary.BigEndian, int64(sendNs)); err != nil {
					fmt.Fprintln(os.Stderr, "write ts error:", err)
					os.Exit(1)
				}
				if _, err := stream.Write(buf[:r]); err != nil {
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
		if err := binary.Write(stream, binary.BigEndian, uint32(0)); err != nil {
			fmt.Fprintln(os.Stderr, "write eof marker error:", err)
			os.Exit(1)
		}
		sendDur = time.Since(tSend)
	}
	_ = stream.Close()
	// Wait for server completion ACK (1 byte). Under some loss patterns the server
	// may close early even if it finished writing; treat this as a warning so we
	// can still report phase timings.
	ack := []byte{0}
	t0 = time.Now()
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	ackOk := 1
	if _, err := io.ReadFull(stream, ack); err != nil {
		ackOk = 0
		fmt.Fprintln(os.Stderr, "[raw-client-warn] read ack error:", err)
	}
	ackDur = time.Since(t0)
	if *postWait > 0 {
		t0 = time.Now()
		t := time.NewTimer(*postWait)
		select {
		case <-ctx.Done():
		case <-t.C:
		}
		postWaitDur = time.Since(t0)
	}
	_ = conn.CloseWithError(0, "")

	dur := time.Since(start)
	mbps := (float64(n) * 8 / 1e6) / dur.Seconds()
	fmt.Fprintf(os.Stderr, "[raw-client] sent=%s bytes=%d dur_ms=%d goodput_mbps=%.3f\n", base, n, dur.Milliseconds(), mbps)
	fmt.Fprintf(os.Stderr, "[raw-client-stages] dial_ms=%d open_stream_ms=%d header_ms=%d send_ms=%d ack_ms=%d ack_ok=%d post_wait_ms=%d total_ms=%d\n",
		dialDur.Milliseconds(), openStreamDur.Milliseconds(), headerDur.Milliseconds(), sendDur.Milliseconds(), ackDur.Milliseconds(), ackOk, postWaitDur.Milliseconds(), time.Since(startTotal).Milliseconds())
}
