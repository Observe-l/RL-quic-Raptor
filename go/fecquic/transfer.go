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
		ackEvery = 8
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
		KeepAlivePeriod: 50 * time.Millisecond,
		MaxIdleTimeout:  90 * time.Second,
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
		pkts, encErr := fec.RaptorQEncodeBlock(buf, N, K, L)
		if encErr != nil {
			return encErr
		}
		// Emit datagrams with FEC header
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
				// Best effort pacing: small sleep to avoid bursting
				if err := conn.SendDatagram(b); err != nil {
					// If too large now, skip; or backoff briefly
					var dtle *quic.DatagramTooLargeError
					if errors.As(err, &dtle) {
						// Cannot send now due to MTU, drop repair symbol
						// drop
						dtleCount++
					}
					// other transient errs: small wait
					sendErrs++
					// second attempt (best-effort)
					if err2 := conn.SendDatagram(b); err2 == nil {
						sentDgrams++
						sentBytes += int64(len(b))
					}
				} else {
					sentDgrams++
					sentBytes += int64(len(b))
				}
			}
			// Make this packet train ack-eliciting periodically to allow CC to progress.
			if keepStr != nil {
				dgramsSinceAck++
				if dgramsSinceAck >= ackEvery {
					select { case ackReq <- struct{}{}: default: }
					dgramsSinceAck = 0
				}
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
	fmt.Fprintf(os.Stderr, "[client-stats] dgrams=%d bytes=%d dur_s=%.3f mbps=%.2f errs=%d dtle=%d\n", sentDgrams, sentBytes, dur, mbps, sendErrs, dtleCount)
	return nil
}

// ServerRecvFile listens for a connection on ln, receives the file, verifies SHA256 and writes to outDir.
// Returns the path to the stored file.
func ServerRecvFile(ctx context.Context, ln *quic.Listener, outDir string) (string, error) {
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
	L := int(hdr.ChunkL)
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

	// Prepare file
	var finalBase string
	if baseName != "" {
		finalBase = baseName + ".recv"
	} else {
		finalBase = fmt.Sprintf("qfec_%d.bin", time.Now().UnixNano())
	}
	tmpPath := filepath.Join(outDir, finalBase+".part")
	out, err := os.Create(tmpPath)
	if err != nil {
		return "", err
	}
	defer out.Close()
	// Pre-size for efficiency and to avoid padding leaks
	_ = out.Truncate(int64(hdr.FileSize))

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

	// Metrics
	recvStart := time.Now()
	var rcvDgrams int64
	var decBlocks int64
	var decTime time.Duration

	// RQ state per block
	type dstate struct {
		recv    []fec.Packet
		decoded []byte
		done    bool
	}
	blocks := map[uint16]*dstate{}
	var receivedBytes uint64
	var nextWriteID uint16
	// Loop receiving datagrams until we have FileSize bytes reconstructed
	for receivedBytes < hdr.FileSize {
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return "", err
		}
		rcvDgrams++
		var fh fecwire.FECHeader
		if !fh.UnmarshalBinary(b) {
			continue
		}
		if fh.Scheme != fecwire.SchemeRaptorQ {
			continue
		}
		if int(fh.PayloadLen) > len(b)-fecwire.HeaderLen {
			continue
		}
		data := b[fecwire.HeaderLen : fecwire.HeaderLen+int(fh.PayloadLen)]
		st := blocks[fh.BlockID]
		if st == nil {
			st = &dstate{recv: make([]fec.Packet, 0, int(fh.N))}
			blocks[fh.BlockID] = st
		}
		st.recv = append(st.recv, fec.Packet{Index: int(fh.SymID), Data: append([]byte(nil), data...)})
		// Try to write any ready consecutive blocks starting from nextWriteID
		for {
			s, ok := blocks[nextWriteID]
			if !ok {
				break
			}
			rcvDgrams++
			if s.done {
				if _, err := out.Write(s.decoded); err != nil {
					return "", err
				}
				receivedBytes += uint64(len(s.decoded))
				delete(blocks, nextWriteID)
				nextWriteID++
				continue
			}
			// Can we decode now?
			// We require at least K symbols for this block.
			if len(s.recv) < int(fh.K) {
				break
			}
			maxBlock := int(fh.K) * L
			// Compute exact size for this block based on file size and position
			// Bytes remaining at this position:
			bytesBefore := uint64(int(nextWriteID) * maxBlock)
			if bytesBefore >= hdr.FileSize {
				return "", errors.New("invalid block ordering or size")
			}
			remAtPos := int(hdr.FileSize - bytesBefore)
			if remAtPos > maxBlock {
				remAtPos = maxBlock
			}
			t0 := time.Now()
			decoded, ok := fec.RaptorQDecodeBytes(s.recv, int(fh.N), int(fh.K), L, remAtPos)
			decTime += time.Since(t0)
			if !ok {
				// Need more symbols; exit write loop and wait for more datagrams
				// If we've already collected N symbols and still can't decode, fail fast
				if len(s.recv) >= int(fh.N) {
					return "", errors.New("fec decode failed for block")
				}
				break
			}
			if len(decoded) > remAtPos {
				decoded = decoded[:remAtPos]
			}
			s.decoded = decoded
			s.done = true
			decBlocks++
			// loop will attempt to write it immediately in next iteration
		}
	}
	// Verify SHA
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	sum, _, err := ComputeSHA256(out)
	if err != nil {
		return "", err
	}
	if sum != hdr.SHA256 {
		return "", errors.New("sha256 mismatch")
	}
	finalPath := filepath.Join(outDir, finalBase)
	if err := out.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return "", err
	}
	rdur := time.Since(recvStart).Seconds()
	if rdur < 1e-6 {
		rdur = 1e-6
	}
	mbps2 := (float64(hdr.FileSize) * 8 / 1e6) / rdur
	fmt.Fprintf(os.Stderr, "[server-stats] dgrams=%d blocks=%d decode_ms=%.1f dur_s=%.3f mbps=%.2f -> %s\n", rcvDgrams, decBlocks, float64(decTime.Milliseconds()), rdur, mbps2, finalPath)
	return finalPath, nil
}

// ListenAndServe starts a QUIC listener and serves a single file transfer.
func ListenAndServe(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config) (string, error) {
	if tlsConf == nil {
		return "", errors.New("tlsConf required")
	}
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 2 * time.Second,
		MaxIdleTimeout:  90 * time.Second,
	})
	if err != nil {
		return "", err
	}
	defer ln.Close()
	return ServerRecvFile(ctx, ln, outDir)
}

// ListenAndServeLoop listens on addr and serves multiple transfers until ctx is done.
func ListenAndServeLoop(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config, onStored func(string)) error {
	if tlsConf == nil {
		return errors.New("tlsConf required")
	}
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 2 * time.Second,
		MaxIdleTimeout:  90 * time.Second,
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
		path, err := ServerRecvFile(ctx, ln, outDir)
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
