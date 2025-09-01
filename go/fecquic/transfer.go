package fecquic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/fec"
	"github.com/quic-go/quic-go/internal/fecwire"
)

// Defaults per spec
const (
	DefaultK = 26
	DefaultN = 32
	DefaultL = 1200
)

// SendOptions control ClientSendFile behavior.
type SendOptions struct {
	K, N, L       int
	InsecureTLS   bool
	DropProb      float64
	Seed          int64
	PaceEach      time.Duration
	BlockPause    time.Duration
	WarnDgramSize int           // bytes; 0 disables
	PostWait      time.Duration // linger before closing
	AckEvery      int           // write 1B on a stream every N datagrams (ack-eliciting); <=0 uses default
	Transport     string        // "dgram" (default) or "stream"
}

// ClientSendFile connects and sends a file using QFEC header + RaptorQ symbols over datagrams.
func ClientSendFile(ctx context.Context, addr, alpn, path string, opts SendOptions) error {
	K := opts.K
	if K <= 0 {
		K = DefaultK
	}
	N := opts.N
	if N <= 0 {
		N = DefaultN
	}
	L := opts.L
	if L <= 0 {
		L = DefaultL
	}
	ackEvery := opts.AckEvery
	if ackEvery <= 0 {
		ackEvery = 1
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// Precompute hash and size
	sum, size, err := ComputeSHA256(f)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	tlsConf := &tls.Config{InsecureSkipVerify: opts.InsecureTLS, NextProtos: []string{alpn}}
	qconf := &quic.Config{
		EnableDatagrams: true,
		// Prevent idle timeouts during datagram-heavy transfers by sending frequent PINGs.
		KeepAlivePeriod:                50 * time.Millisecond,
		MaxIdleTimeout:                 90 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
	}
	conn, err := quic.DialAddr(ctx, addr, tlsConf, qconf)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")

	// Send header on a stream
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	hdr := FileHeader{Version: 1, FileSize: uint64(size), SHA256: sum, ChunkL: uint32(L)}
	if _, err := str.Write(hdr.MarshalBinary()); err != nil {
		return err
	}
	// Optional: append base filename length (u16 LE) + bytes to help server naming
	base := filepath.Base(path)
	if len(base) > 0 && len(base) < 65535 {
		var lenb [2]byte
		// avoid importing encoding/binary at top by using a tiny local put
		lenb[0] = byte(len(base))
		lenb[1] = byte(len(base) >> 8)
		if _, err := str.Write(lenb[:]); err != nil {
			return err
		}
		if _, err := str.Write([]byte(base)); err != nil {
			return err
		}
	}
	if err := str.Close(); err != nil {
		return err
	}

	// Open a keepalive stream to periodically send tiny bytes (ack-eliciting)
	// so that the connection doesn't go idle when only sending DATAGRAM frames.
	keepStr, _ := conn.OpenStream()
	keepDone := make(chan struct{})
	kaStop := make(chan struct{})
	// Channel to request ack-eliciting writes without blocking the sender loop.
	ackReq := make(chan struct{}, 32)
	go func() {
		defer close(keepDone)
		if keepStr == nil {
			return
		}
		// Fallback keepalive ticker (when not writing per-ackEvery below)
		t := time.NewTicker(750 * time.Millisecond)
		defer t.Stop()
		b := []byte{0}
		for {
			select {
			case <-ctx.Done():
				return
			case <-kaStop:
				return
			case <-t.C:
				_ = keepStr.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
				_, _ = keepStr.Write(b)
			case <-ackReq:
				_ = keepStr.SetWriteDeadline(time.Now().Add(5 * time.Millisecond))
				_, _ = keepStr.Write(b)
			}
		}
	}()

	// Metrics counters
	start := time.Now()
	var sentDgrams, sentBytes, sendErrs, dtleCount int64
	var dgramsSinceAck int
	var encTime time.Duration
	var sendTime time.Duration

	// Send symbols per block
	buf := make([]byte, K*L)
	blockID := 0
	var rng *rand.Rand
	if opts.DropProb > 0 {
		seed := opts.Seed
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		rng = rand.New(rand.NewSource(seed))
	}
	for {
		n, err := io.ReadFull(f, buf)
		if err == io.ErrUnexpectedEOF || err == io.EOF { // last partial block
			if n == 0 {
				break
			}
			buf = buf[:n]
		} else if err == io.ErrUnexpectedEOF {
			// handled above
		} else if err != nil && err != io.EOF {
			return err
		}
		// Encode block
		tEnc := time.Now()
		pkts, encErr := fec.RaptorQEncodeBlock(buf, N, K, L)
		if encErr != nil {
			return encErr
		}
		encTime += time.Since(tEnc)
		// Emit symbols per chosen transport
		for _, p := range pkts {
			h := fecwire.FECHeader{
				Version:    1,
				Scheme:     fecwire.SchemeRaptorQ,
				BlockID:    uint16(blockID),
				N:          uint8(N),
				K:          uint8(K),
				SymID:      uint8(p.Index),
				PayloadLen: uint32(len(p.Data)),
			}
			b := make([]byte, fecwire.HeaderLen+len(p.Data))
			copy(b[:fecwire.HeaderLen], h.MarshalBinary(nil))
			copy(b[fecwire.HeaderLen:], p.Data)
			if opts.WarnDgramSize > 0 && len(b) > opts.WarnDgramSize {
				fmt.Printf("warn: datagram size %d exceeds threshold %d; consider reducing L or header size\n", len(b), opts.WarnDgramSize)
				opts.WarnDgramSize = 0 // warn once
			}
			if rng != nil && rng.Float64() < opts.DropProb {
				// simulate sender drop
			} else {
				tSend := time.Now()
				if opts.Transport == "stream" {
					// Send on a dedicated uni stream for symbols
					s, err := conn.OpenUniStream()
					if err != nil {
						return err
					}
					if _, err := s.Write(b); err != nil {
						return err
					}
					_ = s.Close()
					sentDgrams++
					sentBytes += int64(len(b))
				} else {
					// Default: datagrams
					if keepStr != nil {
						if ackEvery <= 1 || dgramsSinceAck+1 >= ackEvery {
							select {
							case ackReq <- struct{}{}:
							default:
							}
							dgramsSinceAck = 0
						}
					}
					if err := conn.SendDatagram(b); err != nil {
						var dtle *quic.DatagramTooLargeError
						if errors.As(err, &dtle) {
							dtleCount++
						}
						sendErrs++
						if err2 := conn.SendDatagram(b); err2 == nil {
							sentDgrams++
							sentBytes += int64(len(b))
						}
					} else {
						sentDgrams++
						sentBytes += int64(len(b))
					}
				}
				sendTime += time.Since(tSend)
			}
			// Count towards ack pacing decisions
			if keepStr != nil {
				dgramsSinceAck++
			}
			if opts.PaceEach > 0 {
				time.Sleep(opts.PaceEach)
			}
		}
		blockID++
		if n < K*L { // done
			break
		}
		if opts.BlockPause > 0 {
			time.Sleep(opts.BlockPause)
		}
		// reset buf slice to full size for next block
		if cap(buf) < K*L {
			buf = make([]byte, K*L)
		} else {
			buf = buf[:K*L]
		}
	}
	if opts.PostWait > 0 {
		time.Sleep(opts.PostWait)
	}
	// stop keepalive goroutine
	close(kaStop)
	<-keepDone
	dur := time.Since(start).Seconds()
	if dur < 1e-6 {
		dur = 1e-6
	}
	mbps := (float64(sentBytes) * 8 / 1e6) / dur
	fmt.Fprintf(os.Stderr, "[client-stats] dgrams=%d bytes=%d dur_s=%.3f mbps=%.2f errs=%d dtle=%d enc_ms=%.1f send_ms=%.1f\n", sentDgrams, sentBytes, dur, mbps, sendErrs, dtleCount, float64(encTime.Milliseconds()), float64(sendTime.Milliseconds()))
	return nil
}

// ServerRecvFile listens for a connection on ln, receives the file, verifies SHA256 and writes to outDir.
// Returns the path to the stored file.
func ServerRecvFile(ctx context.Context, ln *quic.Listener, outDir string) (string, error) {
	return ServerRecvFileWithRX(ctx, ln, outDir, RXOptions{})
}

// ServerRecvFileWithRX is like ServerRecvFile but allows configuring the receiver buffer.
func ServerRecvFileWithRX(ctx context.Context, ln *quic.Listener, outDir string, rx RXOptions) (string, error) {
	// Accept one connection
	conn, err := ln.Accept(ctx)
	if err != nil {
		return "", err
	}
	defer conn.CloseWithError(0, "done")

	// Receive header stream
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return "", err
	}
	hdrBytes := make([]byte, fileHeaderLen)
	if _, err := io.ReadFull(stream, hdrBytes); err != nil {
		return "", err
	}
	var hdr FileHeader
	if err := hdr.UnmarshalBinary(hdrBytes); err != nil {
		return "", err
	}
	// Try read optional filename (u16 len + bytes); safe if EOF
	var baseName string
	var lb [2]byte
	n, err := io.ReadFull(stream, lb[:])
	if err == nil && n == 2 {
		need := int(lb[0]) | int(lb[1])<<8
		if need > 0 && need < 4096 { // cap
			buf := make([]byte, need)
			if _, err := io.ReadFull(stream, buf); err == nil {
				baseName = filepath.Base(string(buf))
			}
		}
	}

	// Drain any additional streams (e.g., client keepalive stream) to avoid flow control stalls.
	go func() {
		for {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			_, _ = io.Copy(io.Discard, s)
			_ = s.Close()
		}
	}()
	// Setup RX manager (buffer + decode workers)
	// We don't know K from header directly; it will be carried on datagrams. We'll detect per-block.
	rxm, err := newRXManager(hdr.FileSize, 0 /*K*/, int(hdr.ChunkL), outDir, baseName, rx)
	if err != nil {
		return "", err
	}
	rxm.start(rx)
	recvStart := time.Now()
	var rcvDgrams int64
	// Concurrent receivers: datagrams and uni streams
	cctx, cancelRx := context.WithCancel(ctx)
	defer cancelRx()
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		// wait until file complete
		for {
			if rxm.written.Load() >= hdr.FileSize {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// DATAGRAM receiver
	go func() {
		for {
			if rxm.written.Load() >= hdr.FileSize {
				return
			}
			b, err := conn.ReceiveDatagram(cctx)
			if err != nil {
				if cctx.Err() != nil {
					return
				}
				continue
			}
			rcvDgrams++
			var fh fecwire.FECHeader
			if !fh.UnmarshalBinary(b) || fh.Scheme != fecwire.SchemeRaptorQ {
				continue
			}
			if int(fh.PayloadLen) > len(b)-fecwire.HeaderLen {
				continue
			}
			data := b[fecwire.HeaderLen : fecwire.HeaderLen+int(fh.PayloadLen)]
			maxBlock := int(fh.K) * int(hdr.ChunkL)
			bytesBefore := uint64(int(fh.BlockID) * maxBlock)
			remAtPos := int(hdr.FileSize - bytesBefore)
			if remAtPos > maxBlock {
				remAtPos = maxBlock
			}
			_ = rxm.ingest(fh.BlockID, int(fh.SymID), int(fh.N), int(fh.K), int(hdr.ChunkL), data, remAtPos)
		}
	}()
	// Uni stream receiver (symbols framed as {FEC header}{payload})
	go func() {
		for {
			if rxm.written.Load() >= hdr.FileSize {
				return
			}
			s, err := conn.AcceptUniStream(cctx)
			if err != nil {
				if cctx.Err() != nil {
					return
				}
				continue
			}
			go func(us *quic.ReceiveStream) {
				defer us.CancelRead(0)
				for {
					if rxm.written.Load() >= hdr.FileSize {
						return
					}
					hdrb := make([]byte, fecwire.HeaderLen)
					if _, err := io.ReadFull(us, hdrb); err != nil {
						return
					}
					var fh fecwire.FECHeader
					if !fh.UnmarshalBinary(hdrb) || fh.Scheme != fecwire.SchemeRaptorQ {
						return
					}
					plen := int(fh.PayloadLen)
					if plen <= 0 || plen > 65536 {
						return
					}
					buf := make([]byte, plen)
					if _, err := io.ReadFull(us, buf); err != nil {
						return
					}
					maxBlock := int(fh.K) * int(hdr.ChunkL)
					bytesBefore := uint64(int(fh.BlockID) * maxBlock)
					remAtPos := int(hdr.FileSize - bytesBefore)
					if remAtPos > maxBlock {
						remAtPos = maxBlock
					}
					_ = rxm.ingest(fh.BlockID, int(fh.SymID), int(fh.N), int(fh.K), int(hdr.ChunkL), buf, remAtPos)
				}
			}(s)
		}
	}()
	<-doneCh
	cancelRx()
	finalPath, err := rxm.closeAndFinalize(hdr.SHA256)
	if err != nil {
		return "", err
	}
	rdur := time.Since(recvStart).Seconds()
	if rdur < 1e-6 {
		rdur = 1e-6
	}
	mbps2 := (float64(hdr.FileSize) * 8 / 1e6) / rdur
	// best-effort metric extraction (type assert to access fields)
	if rxm != nil {
		fmt.Fprintf(os.Stderr, "[server-stats] dgrams=%d dur_s=%.3f mbps=%.2f dec_blocks=%d dec_ms=%d drop_repairs=%d -> %s\n",
			rcvDgrams, rdur, mbps2, rxm.decBlocks.Load(), rxm.decTimeTotal.Load(), rxm.dropsRepairs.Load(), finalPath)
	} else {
		fmt.Fprintf(os.Stderr, "[server-stats] dgrams=%d dur_s=%.3f mbps=%.2f -> %s\n", rcvDgrams, rdur, mbps2, finalPath)
	}
	return finalPath, nil
}

// ListenAndServe starts a QUIC listener and serves a single file transfer.
func ListenAndServe(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config) (string, error) {
	if tlsConf == nil {
		return "", errors.New("tlsConf required")
	}
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		EnableDatagrams:                true,
		KeepAlivePeriod:                2 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
	})
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ServerRecvFileWithRX(ctx, ln, outDir, RXOptions{})
}

// ListenAndServeLoop listens on addr and serves multiple transfers until ctx is done.
func ListenAndServeLoop(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config, onStored func(string)) error {
	if tlsConf == nil {
		return errors.New("tlsConf required")
	}
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		EnableDatagrams:                true,
		KeepAlivePeriod:                2 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		path, err := ServerRecvFileWithRX(ctx, ln, outDir, RXOptions{})
		if err != nil {
			// If the context was canceled or deadline exceeded, exit gracefully.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			// Otherwise, continue accepting future transfers.
			continue
		}
		if onStored != nil {
			onStored(path)
		}
	}
}

// ListenAndServeLoopWithRX allows configuring the receiver options.
func ListenAndServeLoopWithRX(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config, rx RXOptions, onStored func(string)) error {
	if tlsConf == nil {
		return errors.New("tlsConf required")
	}
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		EnableDatagrams:                true,
		KeepAlivePeriod:                2 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
	})
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		path, err := ServerRecvFileWithRX(ctx, ln, outDir, rx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			continue
		}
		if onStored != nil {
			onStored(path)
		}
	}
}

// DialAndSend is a helper that dials and sends the file.
func DialAndSend(ctx context.Context, addr, alpn, path string, insecure bool) error {
	return ClientSendFile(ctx, addr, alpn, path, SendOptions{InsecureTLS: insecure})
}

// Helper to generate a minimal self-signed TLS config (server only)
func GenerateServerTLSConfig(alpn string) (*tls.Config, error) {
	// use example echo’s helper logic inline to avoid import cycles
	// Borrowed pattern: generate Ed25519 self-signed cert
	// Minimal duplication here for convenience
	return genSelfSigned(alpn)
}

// genSelfSigned creates a minimal self-signed TLS config with ALPN.
// genSelfSigned is implemented in tls_selfsigned.go

// ResolveUDPAddr validates the addr string, useful for early error catching.
func ResolveUDPAddr(addr string) error {
	_, err := net.ResolveUDPAddr("udp", addr)
	return err
}
