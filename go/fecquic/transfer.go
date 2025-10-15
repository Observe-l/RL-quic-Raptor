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
	"runtime"
	"strconv"
	"time"

	"sync"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/fec"
	"github.com/quic-go/quic-go/internal/fecwire"
	"github.com/quic-go/quic-go/logging"
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
	// ARQ options
	UseARQ         bool    // enable ARQ control plane and on-demand repairs
	InitialRepairs int     // R0: additional repairs to send initially (defaults to N-K if N provided)
	WindowW        int     // max unfinished clusters in flight (0=unlimited)
	RStep          int     // minimum repairs per NACK
	Alpha          float64 // scaling for deficit in ΔR
	MaxAttempts    int     // max ARQ attempts per cluster (0=no cap)
}

// ClientSendFile connects and sends a file using QFEC header + RaptorQ symbols over datagrams.
func ClientSendFile(ctx context.Context, addr, alpn, path string, opts SendOptions) error {
	// Optional pacing; respect QUIC_FEC_CC_BYPASS to eliminate sleeps/waits entirely
	bypass := os.Getenv("QUIC_FEC_CC_BYPASS") == "1"
	var pc *pacer
	if opts.PaceEach > 0 {
		pc = newPacer(opts.PaceEach)
	}
	ecnStats := NewECNStats()
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
	if ackEvery < 0 {
		ackEvery = 1 // negative => use default
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
		// attach our ECN tracer to observe CE/ECT counts
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			return NewECNConnTracer(ecnStats)
		},
		EnableDatagrams: true,
		// Prevent idle timeouts; keep small to avoid tail delays on shutdown.
		KeepAlivePeriod:                20 * time.Millisecond,
		MaxIdleTimeout:                 6 * time.Second,
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
		if keepStr == nil || ackEvery == 0 {
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
	// ARQ metrics
	var totalSymbols int64
	var totalRepairs int64
	var totalAttempts int64
	// pacer/inter-send telemetry
	var lastSend time.Time
	var interSum time.Duration
	var interCount int

	// Live goodput printer
	liveStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-liveStop:
				return
			case <-ticker.C:
				dur := time.Since(start).Seconds()
				if dur < 1e-6 {
					dur = 1e-6
				}
				b := sentBytes
				mbps := (float64(b) * 8 / 1e6) / dur
				_, _, rx0, rx1, rxce, _ := ecnStats.Snapshot()
				fmt.Fprintf(os.Stderr, "[live-client] tx_bytes=%d mbps=%.2f ecn_rx: CE=%d, ECT0=%d, ECT1=%d\n", b, mbps, rxce, rx0, rx1)
			}
		}
	}()

	// Send symbols per block
	buf := make([]byte, K*L)
	blockID := 0
	// If ARQ window enforcement times out once, disable it for the remainder to avoid per-block 5s stalls
	var arqWindowDisabled bool
	var rng *rand.Rand
	if opts.DropProb > 0 {
		seed := opts.Seed
		if seed == 0 {
			seed = time.Now().UnixNano()
		}
		rng = rand.New(rand.NewSource(seed))
	}
	// ARQ: map of active block transmitters
	type blockTx struct {
		K, L       int
		enc        *fec.RaptorQEncoder
		nextESI    int // next repair ESI to send (>=K)
		repairsOut int // how many repairs sent so far
		attempt    int // last processed attempt idx
	}
	txMu := &sync.Mutex{}
	active := make(map[uint16]*blockTx)
	cond := sync.NewCond(txMu)

	// Control reader: accept server control uni stream and react to NACK/ACK
	if opts.UseARQ {
		go func() {
			for {
				us, err := conn.AcceptUniStream(ctx)
				if err != nil {
					return
				}
				// one stream carrying a sequence of control messages
				go func(rs *quic.ReceiveStream) {
					defer rs.CancelRead(0)
					for {
						t, msg, err := readCtrl(rs)
						if err != nil {
							return
						}
						switch t {
						case arqMsgNACK:
							n := msg.(NackNeedMore)
							bid := uint16(n.ClusterID)
							txMu.Lock()
							bt := active[bid]
							txMu.Unlock()
							if bt == nil {
								continue
							}
							// ignore stale attempts (process each attempt index once)
							if int(n.AttemptIdx) <= bt.attempt {
								continue
							}
							// If we've reached the maximum number of ARQ attempts for this block, give up and free a window slot.
							if opts.MaxAttempts > 0 && int(n.AttemptIdx) >= opts.MaxAttempts {
								txMu.Lock()
								delete(active, bid)
								txMu.Unlock()
								cond.Broadcast()
								fmt.Fprintf(os.Stderr, "[arq] giveup block=%d at attempt=%d (max=%d)\n", bid, n.AttemptIdx, opts.MaxAttempts)
								continue
							}
							toSend := int(n.RecommendExtra)
							if toSend <= 0 {
								toSend = 0
							}
							// ΔR policy: max(rec_extra, R_step, ceil(alpha * deficit))
							deficit := 0
							if bt.K-int(n.RxUnique) > 0 {
								deficit = bt.K - int(n.RxUnique)
							}
							rstep := opts.RStep
							if rstep <= 0 {
								rstep = 4
							}
							alpha := opts.Alpha
							if alpha <= 0 {
								alpha = 0.6
							}
							cand := int(alpha*float64(deficit) + 0.9999)
							if cand < rstep {
								cand = rstep
							}
							if cand < toSend {
								cand = toSend
							}
							if cand <= 0 {
								cand = 1
							}
							if cand == 0 {
								// nothing to append
								continue
							}
							// send cand fresh repairs
							for i := 0; i < cand; i++ {
								esi := bt.nextESI
								payload := bt.enc.GenSymbol(uint32(esi))
								// Guard N to avoid overflow and unrealistic growth
								advN := minInt(255, bt.K+bt.repairsOut+1)
								h := fecwire.FECHeader{
									Version:    1,
									Scheme:     fecwire.SchemeRaptorQ,
									BlockID:    bid,
									N:          uint8(advN),
									K:          uint8(bt.K),
									SymID:      uint8(esi),
									PayloadLen: uint32(len(payload)),
								}
								b := make([]byte, fecwire.HeaderLen+len(payload))
								copy(b[:fecwire.HeaderLen], h.MarshalBinary(nil))
								copy(b[fecwire.HeaderLen:], payload)
								if err := conn.SendDatagram(b); err == nil {
									sentDgrams++
									sentBytes += int64(len(b))
									totalSymbols++
									totalRepairs++
								} else {
									sendErrs++
								}
								bt.nextESI++
								bt.repairsOut++
								if pc != nil {
									pc.Wait()
								}
							}
							bt.attempt = int(n.AttemptIdx)
							totalAttempts++
						case arqMsgACK:
							a := msg.(AckSuccess)
							bid := uint16(a.ClusterID)
							txMu.Lock()
							delete(active, bid)
							txMu.Unlock()
							cond.Broadcast()
						}
					}
				}(us)
			}
		}()
	}

	for {
		n, err := io.ReadFull(f, buf)
		if err == io.ErrUnexpectedEOF || err == io.EOF { // last partial block
			if n == 0 {
				break
			}
			buf = buf[:n]
		} else if err != nil && err != io.EOF {
			return err
		}
		// Enforce ARQ window to limit unfinished clusters.
		// If a timeout is hit once, disable further gating to avoid cumulative stalls.
		if opts.UseARQ && opts.WindowW > 0 && !arqWindowDisabled {
			deadline := time.Now().Add(1 * time.Second)
			for {
				txMu.Lock()
				n := len(active)
				txMu.Unlock()
				if n < opts.WindowW {
					break
				}
				if time.Now().After(deadline) {
					fmt.Fprintf(os.Stderr, "[arq] window wait timeout; proceeding n=%d W=%d; disabling window gating\n", n, opts.WindowW)
					arqWindowDisabled = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		// Prepare encoder for this block so we can generate on-demand repairs later
		blockBytes := make([]byte, len(buf))
		copy(blockBytes, buf)
		tEnc := time.Now()
		enc, encErr := fec.NewRaptorQEncoder(blockBytes, K, L)
		if encErr != nil {
			return encErr
		}
		encTime += time.Since(tEnc)
		// Decide initial symbols count
		initRepairs := opts.InitialRepairs
		if initRepairs <= 0 {
			initRepairs = maxInt(0, N-K)
		}
		// Allow large initial parity: header N will still be clamped to 255 and pacing/rate control will shape traffic.
		initN := K + initRepairs
		if initN < K {
			initN = K
		}
		// Initialize attempt to -1 so the first NACK with attempt_idx=0 is processed once.
		bt := &blockTx{K: K, L: L, enc: enc, nextESI: K, repairsOut: 0, attempt: -1}
		txMu.Lock()
		active[uint16(blockID)] = bt
		txMu.Unlock()
		// Emit initial symbols 0..initN-1
		for esi := 0; esi < initN; esi++ {
			payload := enc.GenSymbol(uint32(esi))
			// Advertise a stable N that doesn't explode with many appends; cap to 255.
			advN := minInt(255, initN)
			h := fecwire.FECHeader{
				Version:    1,
				Scheme:     fecwire.SchemeRaptorQ,
				BlockID:    uint16(blockID),
				N:          uint8(advN),
				K:          uint8(K),
				SymID:      uint8(esi),
				PayloadLen: uint32(len(payload)),
			}
			b := make([]byte, fecwire.HeaderLen+len(payload))
			copy(b[:fecwire.HeaderLen], h.MarshalBinary(nil))
			copy(b[fecwire.HeaderLen:], payload)
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
				// pacer: inter-send delta logging (avg every ~200 packets)
				if !lastSend.IsZero() {
					delta := tSend.Sub(lastSend)
					interSum += delta
					interCount++
					if interCount >= 200 {
						avg := float64(interSum.Microseconds()) / float64(interCount)
						fmt.Fprintf(os.Stderr, "[pacer] avg_inter_us=%.0f\n", avg)
						interSum = 0
						interCount = 0
					}
				}
				lastSend = tSend
				sendTime += time.Since(tSend)
				totalSymbols++
				if esi >= K {
					totalRepairs++
				}
			}
			// Count towards ack pacing decisions
			if keepStr != nil {
				dgramsSinceAck++
			}
			if pc != nil {
				pc.Wait()
			}
			if esi >= K {
				bt.nextESI = esi + 1
				bt.repairsOut = (esi + 1) - K
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
	// If ARQ is enabled, optionally drain outstanding blocks before closing unless bypassing waits.
	// This ensures NACK/ACK rounds can complete on high RTT/DDL links.
	if opts.UseARQ && !bypass {
		// Wait until all active blocks have been ACKed or until a cap.
		// Base cap defaults to max(PostWait, 3s). If RTT_MS env is present, ensure at least ~10 RTTs (capped at 10s).
		drainCap := 3 * time.Second
		if opts.PostWait > drainCap {
			drainCap = opts.PostWait
		}
		if rttStr := os.Getenv("RTT_MS"); rttStr != "" {
			if ms, err := strconv.Atoi(rttStr); err == nil && ms > 0 {
				rttDur := time.Duration(ms) * time.Millisecond
				minDrain := 10 * rttDur
				if minDrain > 10*time.Second {
					minDrain = 10 * time.Second
				}
				if minDrain > drainCap {
					drainCap = minDrain
				}
			}
		}
		deadline := time.Now().Add(drainCap)
		// Poll with short sleeps to avoid indefinite waits on missing broadcasts.
		for time.Now().Before(deadline) {
			txMu.Lock()
			n := len(active)
			txMu.Unlock()
			if n == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	// Optional tail wait after ARQ drain; skip when bypassing waits
	if opts.PostWait > 0 && !bypass {
		time.Sleep(opts.PostWait)
	}
	// stop live printer and keepalive goroutine after ARQ drain
	close(liveStop)
	close(kaStop)
	<-keepDone
	// Final stats
	dur := time.Since(start).Seconds()
	if dur < 1e-6 {
		dur = 1e-6
	}
	mbps := (float64(sentBytes) * 8 / 1e6) / dur
	fmt.Fprintf(os.Stderr, "[client-stats] dgrams=%d bytes=%d dur_s=%.3f mbps=%.2f errs=%d dtle=%d enc_ms=%.1f send_ms=%.1f\n",
		sentDgrams, sentBytes, dur, mbps, sendErrs, dtleCount, float64(encTime.Milliseconds()), float64(sendTime.Milliseconds()))
	if opts.UseARQ {
		overhead := 0.0
		if totalSymbols > 0 {
			overhead = float64(totalRepairs) / float64(totalSymbols) * 100.0
		}
		fmt.Fprintf(os.Stderr, "[arq-stats] clusters=%d attempts=%d symbols_total=%d repairs=%d overhead_pct=%.1f\n",
			blockID, totalAttempts, totalSymbols, totalRepairs, overhead)
	}
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

	// Receive header: find the stream that starts with magic "QFEC"
	var (
		hdrBytes = make([]byte, fileHeaderLen)
		hdr      FileHeader
		baseName string
	)
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return "", err
		}
		// peek magic
		if _, err := io.ReadFull(s, hdrBytes[:4]); err != nil {
			// not enough data; drain and continue
			_, _ = io.Copy(io.Discard, s)
			_ = s.Close()
			continue
		}
		if string(hdrBytes[:4]) != fileHeaderMagic {
			// not our header; drain
			_, _ = io.Copy(io.Discard, s)
			_ = s.Close()
			continue
		}
		// read the rest of the header
		if _, err := io.ReadFull(s, hdrBytes[4:]); err != nil {
			return "", err
		}
		if err := hdr.UnmarshalBinary(hdrBytes); err != nil {
			return "", err
		}
		// Try read optional filename (u16 len + bytes); safe if EOF
		var lb [2]byte
		n, err := io.ReadFull(s, lb[:])
		if err == nil && n == 2 {
			need := int(lb[0]) | int(lb[1])<<8
			if need > 0 && need < 4096 { // cap
				buf := make([]byte, need)
				if _, err := io.ReadFull(s, buf); err == nil {
					baseName = filepath.Base(string(buf))
				}
			}
		}
		// header parsed; done
		break
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
	// open a control uni stream to client for ACK/NACK
	ctrlStr, _ := conn.OpenUniStream()
	if ctrlStr != nil {
		rxm.ctrlW = ctrlStr
		// ctrlOut will be created in rxm.start when ctrlW is set
	}
	rxm.start(rx)
	recvStart := time.Now()
	var rcvDgrams int64
	// Concurrent receivers: datagrams and uni streams
	cctx, cancelRx := context.WithCancel(ctx)
	defer cancelRx()
	doneCh := make(chan struct{})
	// progress ticker for visibility
	progStop := make(chan struct{})
	go func() {
		if rxm == nil {
			return
		}
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-progStop:
				return
			case <-t.C:
				w := rxm.written.Load()
				if w > 0 {
					fmt.Fprintf(os.Stderr, "[server-progress] written=%d/%d\n", w, hdr.FileSize)
				}
			}
		}
	}()
	go func() {
		defer close(doneCh)
		// Wait until file complete OR context done OR prolonged inactivity in writes.
		// Treat either write progress or datagram arrivals as activity to avoid premature finalize
		// on high-loss/high-parity runs where writes can stall while arrivals continue.
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		lastWritten := rxm.written.Load()
		lastWriteChange := time.Now()
		lastDgrams := rcvDgrams
		lastDgramChange := time.Now()
		// Make inactivity more tolerant for high-RTT/high-redundancy runs.
		inactivity := 3 * time.Second
		if rx.DDL > 0 {
			if d := 2 * rx.DDL; d > inactivity {
				inactivity = d
			}
		}
		if inactivity < 6*time.Second {
			inactivity = 6 * time.Second
		}
		for {
			if rxm.written.Load() >= hdr.FileSize {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w := rxm.written.Load()
				if w != lastWritten {
					lastWritten = w
					lastWriteChange = time.Now()
				}
				if rcvDgrams != lastDgrams {
					lastDgrams = rcvDgrams
					lastDgramChange = time.Now()
				}
				if time.Since(lastWriteChange) > inactivity && time.Since(lastDgramChange) > inactivity {
					return
				}
			}
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
			if rcvDgrams%500 == 0 {
				fmt.Fprintf(os.Stderr, "[server-progress] dgrams=%d written=%d/%d\n", rcvDgrams, rxm.written.Load(), hdr.FileSize)
			}
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
					if plen <= 0 || plen > 1<<20 {
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
	// wait for reception to complete
	<-doneCh
	cancelRx()
	close(progStop)
	finalPath, err := rxm.closeAndFinalize(hdr.SHA256)
	if err != nil {
		// On failure (e.g., SHA mismatch / residual erasures), still emit a best-effort observation
		// so external harnesses don't stall waiting for metrics.
		if rxm != nil && rxm.met != nil {
			obs := rxm.met.Snapshot(time.Now())
			// Mark residual erasures on failure path.
			obs.ResidualErasures = 1
			obs.PrintJSON()
		}
		// Log the error reason for diagnostics
		fmt.Fprintf(os.Stderr, "[server-error] finalize: %v\n", err)
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
		if rxm.met != nil {
			obs := rxm.met.Snapshot(time.Now())
			obs.PrintJSON()
		}
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
	ecnStats := NewECNStats()
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			return NewECNConnTracer(ecnStats)
		},
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
	path, err := ServerRecvFileWithRX(ctx, ln, outDir, RXOptions{})
	if err == nil && ecnStats != nil {
		tx0, tx1, rx0, rx1, rxce, _ := ecnStats.Snapshot()
		fmt.Fprintf(os.Stderr, "[server-ecn] rx: CE=%d ECT0=%d ECT1=%d, tx: ECT0=%d ECT1=%d\n", rxce, rx0, rx1, tx0, tx1)
	}
	return path, err
}

// ListenAndServeLoop listens on addr and serves multiple transfers until ctx is done.
func ListenAndServeLoop(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config, onStored func(string)) error {
	if tlsConf == nil {
		return errors.New("tlsConf required")
	}
	ecnStats := NewECNStats()
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			return NewECNConnTracer(ecnStats)
		},
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
		if ecnStats != nil {
			tx0, tx1, rx0, rx1, rxce, _ := ecnStats.Snapshot()
			fmt.Fprintf(os.Stderr, "[server-ecn] rx: CE=%d ECT0=%d ECT1=%d, tx: ECT0=%d ECT1=%d\n", rxce, rx0, rx1, tx0, tx1)
		}
	}
}

// pacer ensures inter-send spacing with microsecond-level precision shared across goroutines.
// It maintains a target schedule and sleeps/yields to hit deadlines without accumulating drift.
type pacer struct {
	mu       sync.Mutex
	nextDue  time.Time
	interval time.Duration
}

func newPacer(interval time.Duration) *pacer {
	if interval <= 0 {
		return nil
	}
	return &pacer{interval: interval}
}

// Wait blocks until the next scheduled time, then advances the schedule by interval.
// It is safe for concurrent use; calls are serialized to maintain spacing across senders.
func (p *pacer) Wait() {
	if p == nil {
		return
	}
	// Reserve the next slot and compute its due time.
	p.mu.Lock()
	due := p.nextDue
	now := time.Now()
	if due.IsZero() || now.After(due) {
		// If we're behind or uninitialized, schedule from now.
		due = now.Add(p.interval)
	} else {
		// Otherwise, move to the next slot.
		due = due.Add(p.interval)
	}
	p.nextDue = due
	p.mu.Unlock()

	// Sleep until due. Use a coarse sleep, then fine-yield to improve precision.
	for {
		rem := time.Until(due)
		if rem <= 0 {
			return
		}
		if rem > 150*time.Microsecond {
			time.Sleep(rem - 100*time.Microsecond)
			continue
		}
		// Sub-150us: yield in small chunks to avoid burning CPU while improving accuracy.
		if rem > 50*time.Microsecond {
			time.Sleep(50 * time.Microsecond)
		} else {
			runtime.Gosched()
		}
	}
}

// ListenAndServeLoopWithRX allows configuring the receiver options.
func ListenAndServeLoopWithRX(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config, rx RXOptions, onStored func(string)) error {
	if tlsConf == nil {
		return errors.New("tlsConf required")
	}
	ecnStats := NewECNStats()
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			return NewECNConnTracer(ecnStats)
		},
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
		if ecnStats != nil {
			tx0, tx1, rx0, rx1, rxce, _ := ecnStats.Snapshot()
			fmt.Fprintf(os.Stderr, "[server-ecn] rx: CE=%d ECT0=%d ECT1=%d, tx: ECT0=%d ECT1=%d\n", rxce, rx0, rx1, tx0, tx1)
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

// small helpers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
