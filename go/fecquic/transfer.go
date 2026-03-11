package fecquic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

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

	txStatsMagic   = "QFST" // QFEC sender stats
	txStatsVersion = 1
)

func doneFlushGrace() time.Duration {
	grace := 500 * time.Millisecond
	if srtt := latestServerSRTT(); srtt > 0 {
		if cand := 4 * srtt; cand > grace {
			grace = cand
		}
	}
	if v := os.Getenv("QUIC_FEC_DONE_GRACE_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil {
			if ms <= 0 {
				return 0
			}
			return time.Duration(ms) * time.Millisecond
		}
	}
	if grace > 2*time.Second {
		grace = 2 * time.Second
	}
	return grace
}

// SendOptions control ClientSendFile behavior.
type SendOptions struct {
	K, N, L     int
	InsecureTLS bool
	DropProb    float64
	Seed        int64
	DialTimeout time.Duration // bounds dialing + QUIC handshake; 0 means "use ctx"
	PaceEach    time.Duration
	BlockPause  time.Duration
	// RxDDL is the receiver ARQ soft deadline (DDL_MS), sent once in the FileHeader.
	// The server applies it to schedule NACKs for seen blocks (idle-from-lastSymAt).
	// 0 means "not specified".
	RxDDL         time.Duration
	WarnDgramSize int           // bytes; 0 disables
	PostWait      time.Duration // linger before closing
	AckEvery      int           // write 1B on a stream every N datagrams (ack-eliciting); <=0 uses default
	Transport     string        // "dgram" (default) or "stream"
	// ARQ options
	UseARQ         bool // enable ARQ control plane and on-demand repairs
	InitialRepairs int  // R0: initial repair symbols (>=0 exact; -1=auto: max(0, N-K))
	WindowW        int  // max unfinished clusters in flight (0=unlimited)
	RStep          int  // minimum repairs per NACK
	MaxAttempts    int  // max ARQ attempts per cluster (0=no cap)
}

// ClientSendFile connects and sends a file using QFEC header + RaptorQ symbols over datagrams.
func ClientSendFile(ctx context.Context, addr, alpn, path string, opts SendOptions) error {
	// Phase timing (client-side)
	startTotal := time.Now()
	var dialDur, hdrDur, sendBlocksDur, arqDrainDur, txStatsDur, postWaitDur, keepStopDur time.Duration
	// Optional pacing (set via -pace / PACE_US)
	var pc *pacer
	if opts.PaceEach > 0 {
		pc = newPacer(opts.PaceEach)
	}
	// At very small pacing intervals (e.g. ~100us at 100Mbps), doing a full pacing wait
	// after every packet can become noticeable overhead. Batch pacing amortizes this cost
	// by allowing short bursts while preserving the long-term average schedule.
	if pc != nil {
		paceBatch := 1
		if v := os.Getenv("PACE_BATCH"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				paceBatch = n
			}
		} else if opts.PaceEach > 0 && opts.PaceEach <= 250*time.Microsecond {
			paceBatch = 8
		}
		pc.SetBatch(paceBatch)
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

	enableQuicStats := os.Getenv("QUIC_FEC_STATS") == "1"
	var quicStats *quicConnStats
	if enableQuicStats {
		quicStats = newQuicConnStats()
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// Match raw QUIC behavior: do not precompute checksums on the sender.
	// File integrity is verified by the experiment harness (md5) on the final output.
	st, err := f.Stat()
	if err != nil {
		return err
	}
	sz := st.Size()
	if sz < 0 {
		return errors.New("negative file size")
	}
	size := uint64(sz)
	var sum [32]byte // zero => receiver will skip SHA verification

	tlsConf := &tls.Config{InsecureSkipVerify: opts.InsecureTLS, NextProtos: []string{alpn}}
	qconf := &quic.Config{
		// attach our ECN tracer to observe CE/ECT counts
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			base := logging.NewMultiplexedConnectionTracer(
				NewECNConnTracer(ecnStats),
				NewCCDebugConnTracer(),
			)
			if !enableQuicStats {
				return devWrapConnTracer(base)
			}
			return devWrapConnTracer(logging.NewMultiplexedConnectionTracer(base, newQuicConnStatsTracer(quicStats)))
		},
		EnableDatagrams: true,
		// Prevent idle timeouts; keep small to avoid tail delays on shutdown.
		KeepAlivePeriod:                20 * time.Millisecond,
		MaxIdleTimeout:                 6 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
	}
	t0 := time.Now()
	dialCtx := ctx
	cancelDial := func() {}
	if opts.DialTimeout > 0 {
		dialCtx, cancelDial = context.WithTimeout(ctx, opts.DialTimeout)
	}
	conn, err := quic.DialAddr(dialCtx, addr, tlsConf, qconf)
	cancelDial()
	if err != nil {
		return err
	}
	dialDur = time.Since(t0)
	defer conn.CloseWithError(0, "done")

	// Send header on a stream
	t0 = time.Now()
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	hdr := FileHeader{Version: 1, FileSize: uint64(size), SHA256: sum, ChunkL: uint32(L)}
	if opts.RxDDL > 0 {
		hdr.RxDDLMS = uint32(opts.RxDDL.Milliseconds())
	}
	if opts.MaxAttempts > 0 {
		hdr.MaxARQAttempts = uint32(opts.MaxAttempts)
	}
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
	hdrDur = time.Since(t0)

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

	// Symbol transport (stream mode): send all symbols on a single uni stream.
	// This avoids the heavy per-symbol stream creation overhead.
	var symStream *quic.SendStream
	var symMu sync.Mutex
	if opts.Transport == "stream" {
		s, err := conn.OpenUniStreamSync(ctx)
		if err != nil {
			return err
		}
		symStream = s
		defer func() { _ = symStream.Close() }()
	}

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

	sendSymbol := func(b []byte) error {
		if opts.Transport == "stream" {
			symMu.Lock()
			defer symMu.Unlock()
			_, err := symStream.Write(b)
			return err
		}
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
			return err
		}
		return nil
	}

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
	sendBlocksStart := time.Now()
	readBuf := make([]byte, K*L)
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

	// DONE ACK (server->client) via control uni-stream.
	// Enabled by default; disable with QUIC_FEC_WAIT_DONE=0.
	waitDone := os.Getenv("QUIC_FEC_WAIT_DONE") != "0"
	doneMsgCh := make(chan DoneFile, 1)
	var doneSeen sync.Once
	connDoneCh := conn.Context().Done()

	// Control reader: accept server control uni stream(s) and react to NACK/ACK/DONE.
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
					case arqMsgDONE:
						if !waitDone {
							return
						}
						d := msg.(DoneFile)
						doneSeen.Do(func() {
							select {
							case doneMsgCh <- d:
							default:
							}
						})
						return
					case arqMsgNACK:
						if !opts.UseARQ {
							continue
						}
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
						if toSend < 0 {
							toSend = 0
						}
						// Policy: append exactly (rec_extra + R_step) repair symbols on every NACK.
						deficit := 0
						if bt.K-int(n.RxUnique) > 0 {
							deficit = bt.K - int(n.RxUnique)
						}
						rstep := opts.RStep
						// Semantics: Rstep=0 means "no extra". Negative values fall back to default.
						if rstep < 0 {
							rstep = 4
						}
						// Policy: append repairs on every NACK, but avoid many small ARQ rounds.
						// Ensure we send at least enough to cover the current deficit, capped.
						cand := toSend + rstep
						maxBurst := 24
						if v := os.Getenv("QUIC_FEC_ARQ_MAX_REPAIR_BURST"); v != "" {
							if n, err := strconv.Atoi(v); err == nil && n > 0 {
								maxBurst = n
							}
						}
						if deficit > 0 {
							need := deficit
							if need > maxBurst {
								need = maxBurst
							}
							if need > cand {
								cand = need
							}
						}
						// Wire format uses uint8 SymID. Do not allow ESI to exceed 255, otherwise
						// SymID wraps and we start re-sending duplicate IDs (wasting bandwidth and
						// preventing decoding from ever finishing).
						if bt.nextESI >= 256 {
							continue
						}
						remain := 256 - bt.nextESI
						if cand > remain {
							cand = remain
						}
						if cand <= 0 {
							continue
						}
						devARQOnClientNack(n, deficit, cand, bt.K, bt.nextESI, bt.repairsOut)
						// send cand fresh repairs
						for i := 0; i < cand; i++ {
							if ctx.Err() != nil {
								return
							}
							esi := bt.nextESI
							payload := bt.enc.GenSymbol(uint32(esi))
							// Avoid per-packet allocation: reuse a fixed-size buffer.
							// SendDatagram copies the slice before returning, so reuse is safe.
							b := make([]byte, fecwire.HeaderLen+bt.L)
							pay := b[fecwire.HeaderLen:]
							if len(payload) == bt.L {
								copy(pay, payload)
							} else {
								clear(pay)
								copy(pay, payload)
							}
							// Guard N to avoid overflow and unrealistic growth
							advN := minInt(255, bt.K+bt.repairsOut+1)
							h := fecwire.FECHeader{
								Version:    1,
								Scheme:     fecwire.SchemeRaptorQ,
								BlockID:    bid,
								N:          uint8(advN),
								K:          uint8(bt.K),
								SymID:      uint8(esi),
								PayloadLen: uint32(bt.L),
							}
							h.MarshalBinary(b[:fecwire.HeaderLen])
							if err := sendSymbol(b); err == nil {
								sentDgrams++
								sentBytes += int64(len(b))
								totalSymbols++
								totalRepairs++
								devARQOnClientRepairSent(bid, esi)
							} else {
								sendErrs++
							}
							bt.nextESI++
							bt.repairsOut++
							if pc != nil {
								pc.AfterSend()
							}
						}
						bt.attempt = int(n.AttemptIdx)
						totalAttempts++
					case arqMsgACK:
						if !opts.UseARQ {
							continue
						}
						a := msg.(AckSuccess)
						devARQOnClientAck(a)
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

	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := io.ReadFull(f, readBuf)
		if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		blockData := readBuf[:n]
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
		// For the last (partial) block, shrink K so we don't transmit padding-only
		// systematic symbols. R0 / Rstep behavior remains unchanged.
		curK := K
		blockDataLen := n
		if blockDataLen < 0 {
			blockDataLen = 0
		}
		if blockDataLen < K*L {
			curK = (blockDataLen + L - 1) / L // ceil
			if curK < 1 {
				curK = 1
			}
			if curK > K {
				curK = K
			}
		}
		// Always pad the source block to exactly curK*L bytes.
		blockBytes := make([]byte, curK*L)
		copy(blockBytes, blockData)
		if blockDataLen > curK*L {
			blockDataLen = curK * L
		}
		tEnc := time.Now()
		enc, encErr := fec.NewRaptorQEncoder(blockBytes, curK, L)
		if encErr != nil {
			return encErr
		}
		encTime += time.Since(tEnc)
		// Decide initial symbols count.
		// Semantics:
		//   InitialRepairs >= 0: send exactly that many initial repair symbols (0 allowed).
		//   InitialRepairs < 0:  auto = max(0, N-K) for backward-compat / convenience.
		initRepairs := opts.InitialRepairs
		if initRepairs < 0 {
			initRepairs = maxInt(0, N-K)
		}
		// Allow large initial parity: header N will still be clamped to 255 and pacing/rate control will shape traffic.
		initN := curK + initRepairs
		if initN < curK {
			initN = curK
		}
		// SymID is uint8 on the wire; do not emit more than 256 distinct symbol IDs per block.
		if initN > 256 {
			initN = 256
		}
		// Initialize attempt to -1 so the first NACK with attempt_idx=0 is processed once.
		bt := &blockTx{K: curK, L: L, enc: enc, nextESI: curK, repairsOut: 0, attempt: -1}
		txMu.Lock()
		active[uint16(blockID)] = bt
		txMu.Unlock()
		// Emit initial symbols 0..initN-1
		for esi := 0; esi < initN; esi++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			var b []byte
			var pay []byte
			payloadLen := L
			// Fast path: for systematic source symbols, avoid the RaptorQ library call.
			// At high bitrates (e.g., 100 Mbps), per-symbol overhead can dominate and
			// cap throughput well below the shaped rate. The RaptorQ systematic symbols
			// are exactly the original data partitioned into L-byte chunks, with the
			// final symbol padded with zeros if needed.
			if esi < curK {
				start := esi * L
				payloadLen = 0
				if start < blockDataLen {
					payloadLen = blockDataLen - start
					if payloadLen > L {
						payloadLen = L
					}
				}
				// Send only the non-padding bytes. Receiver will treat missing tail as zeros.
				b = make([]byte, fecwire.HeaderLen+payloadLen)
				pay = b[fecwire.HeaderLen:]
				if payloadLen > 0 {
					copy(pay, blockBytes[start:start+payloadLen])
				}
			} else {
				b = make([]byte, fecwire.HeaderLen+L)
				pay = b[fecwire.HeaderLen:]
				payload := enc.GenSymbol(uint32(esi))
				if len(payload) == L {
					copy(pay, payload)
				} else {
					clear(pay)
					copy(pay, payload)
				}
			}
			// Advertise a stable N that doesn't explode with many appends; cap to 255.
			advN := minInt(255, initN)
			h := fecwire.FECHeader{
				Version:    1,
				Scheme:     fecwire.SchemeRaptorQ,
				BlockID:    uint16(blockID),
				N:          uint8(advN),
				K:          uint8(curK),
				SymID:      uint8(esi),
				PayloadLen: uint32(payloadLen),
			}
			h.MarshalBinary(b[:fecwire.HeaderLen])
			if opts.WarnDgramSize > 0 && len(b) > opts.WarnDgramSize {
				fmt.Printf("warn: datagram size %d exceeds threshold %d; consider reducing L or header size\n", len(b), opts.WarnDgramSize)
				opts.WarnDgramSize = 0 // warn once
			}
			if rng != nil && rng.Float64() < opts.DropProb {
				// simulate sender drop
			} else {
				tSend := time.Now()
				if err := sendSymbol(b); err != nil {
					sendErrs++
					if opts.Transport == "stream" {
						return err
					}
					// For datagrams, attempt a single retry since packet size can shrink temporarily.
					if err2 := sendSymbol(b); err2 == nil {
						sentDgrams++
						sentBytes += int64(len(b))
					}
				} else {
					sentDgrams++
					sentBytes += int64(len(b))
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
				if esi >= curK {
					totalRepairs++
				}
			}
			// Count towards ack pacing decisions
			if keepStr != nil {
				dgramsSinceAck++
			}
			if pc != nil {
				pc.AfterSend()
			}
			if esi >= curK {
				bt.nextESI = esi + 1
				bt.repairsOut = (esi + 1) - curK
			}
		}
		blockID++
		if err == io.ErrUnexpectedEOF || err == io.EOF {
			break
		}
		if opts.BlockPause > 0 {
			time.Sleep(opts.BlockPause)
		}
	}
	sendBlocksDur = time.Since(sendBlocksStart)
	// If ARQ is enabled, drain outstanding blocks before closing.
	// NOTE: Do not tie reliability to congestion control mode. Skipping this drain can
	// cause sha256 mismatch / residual erasures when the client exits before ARQ completes.
	skipDrain := os.Getenv("QUIC_FEC_SKIP_ARQ_DRAIN") == "1"
	if opts.UseARQ && !skipDrain {
		drainStart := time.Now()
		// Wait until all active blocks have been ACKed or until a cap.
		// Base cap defaults to max(PostWait, 15s).
		// This prevents premature close under loss where ARQ may need multiple RTTs.
		// For RL / fast experiments, override with QUIC_FEC_ARQ_DRAIN_CAP_MS.
		drainCap := 15 * time.Second
		if capStr := os.Getenv("QUIC_FEC_ARQ_DRAIN_CAP_MS"); capStr != "" {
			if ms, err := strconv.Atoi(capStr); err == nil {
				if ms <= 0 {
					drainCap = 0
				} else {
					drainCap = time.Duration(ms) * time.Millisecond
				}
			}
		}
		if opts.PostWait > drainCap {
			drainCap = opts.PostWait
		}
		if rttStr := os.Getenv("RTT_MS"); rttStr != "" {
			if ms, err := strconv.Atoi(rttStr); err == nil && ms > 0 {
				rttDur := time.Duration(ms) * time.Millisecond
				minDrain := 10 * rttDur
				if minDrain > drainCap {
					drainCap = minDrain
				}
			}
		}
		if drainCap <= 0 {
			// Explicitly disabled: skip drain but keep the connection alive
			// to allow stats and DONE ACK reception.
			arqDrainDur = time.Since(drainStart)
			goto afterArqDrain
		}
		deadline := time.Now().Add(drainCap)
		// Poll with short sleeps to avoid indefinite waits on missing broadcasts.
		for time.Now().Before(deadline) {
			if err := ctx.Err(); err != nil {
				return err
			}
			txMu.Lock()
			n := len(active)
			txMu.Unlock()
			if n == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		arqDrainDur = time.Since(drainStart)
	}

afterArqDrain:
	// Send sender-side symbol counters to the server so it can compute fec_overhead.
	// This is done after ARQ drain so counts reflect all appended repairs.
	{
		tStatsStart := time.Now()
		txSourceSymbols := totalSymbols - totalRepairs
		if txSourceSymbols < 0 {
			txSourceSymbols = 0
		}
		if totalRepairs < 0 {
			totalRepairs = 0
		}
		us, err := conn.OpenUniStreamSync(ctx)
		if err == nil {
			buf := make([]byte, 4+1+8+8)
			copy(buf[:4], txStatsMagic)
			buf[4] = byte(txStatsVersion)
			binary.LittleEndian.PutUint64(buf[5:13], uint64(txSourceSymbols))
			binary.LittleEndian.PutUint64(buf[13:21], uint64(totalRepairs))
			_, _ = us.Write(buf)
			_ = us.Close()
		}
		txStatsDur = time.Since(tStatsStart)
	}

	// Wait for receiver DONE ACK (server-driven completion) to avoid time-based tail waits.
	// This is analogous to quic-raw's 1-byte completion ACK.
	if waitDone {
		t0 = time.Now()
		select {
		case d := <-doneMsgCh:
			fmt.Fprintf(os.Stderr, "[fec-client-done] wait_ms=%d ok=%d written=%d\n", time.Since(t0).Milliseconds(), d.Ok, d.Written)
			if d.Ok == 0 {
				return fmt.Errorf("receiver reported not-ok (ok=0) written=%d", d.Written)
			}
		case <-connDoneCh:
			txMu.Lock()
			pending := len(active)
			txMu.Unlock()
			cause := context.Cause(conn.Context())
			var appErr *quic.ApplicationError
			if errors.As(cause, &appErr) && appErr.Remote && appErr.ErrorCode == 0 {
				fmt.Fprintf(os.Stderr, "[fec-client-done] wait_ms=%d ok=1 written=unknown fallback=remote_close pending=%d\n", time.Since(t0).Milliseconds(), pending)
				break
			}
			if pending == 0 {
				fmt.Fprintf(os.Stderr, "[fec-client-done] wait_ms=%d ok=1 written=unknown fallback=conn_closed cause=%v\n", time.Since(t0).Milliseconds(), cause)
				break
			}
			return fmt.Errorf("connection closed before DONE with %d pending blocks: %w", pending, cause)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	// Optional tail wait after ARQ drain
	if opts.PostWait > 0 && !skipDrain {
		t0 = time.Now()
		time.Sleep(opts.PostWait)
		postWaitDur = time.Since(t0)
	}
	// stop live printer and keepalive goroutine after ARQ drain
	t0 = time.Now()
	close(liveStop)
	close(kaStop)
	<-keepDone
	keepStopDur = time.Since(t0)
	// Final stats
	dur := time.Since(start).Seconds()
	if dur < 1e-6 {
		dur = 1e-6
	}
	mbps := (float64(sentBytes) * 8 / 1e6) / dur
	fmt.Fprintf(os.Stderr, "[client-stats] dgrams=%d bytes=%d dur_s=%.3f mbps=%.2f errs=%d dtle=%d enc_ms=%.1f send_ms=%.1f\n",
		sentDgrams, sentBytes, dur, mbps, sendErrs, dtleCount, float64(encTime.Milliseconds()), float64(sendTime.Milliseconds()))
	if opts.UseARQ {
		txSourceSymbols := totalSymbols - totalRepairs
		if txSourceSymbols < 0 {
			txSourceSymbols = 0
		}
		overhead := 0.0
		if txSourceSymbols > 0 {
			overhead = float64(totalRepairs) / float64(txSourceSymbols)
		}
		fmt.Fprintf(os.Stderr, "[arq-stats] clusters=%d attempts=%d tx_total_symbols=%d tx_source_symbols=%d tx_repairs=%d fec_overhead=%.3f\n",
			blockID, totalAttempts, totalSymbols, txSourceSymbols, totalRepairs, overhead)
	}
	fmt.Fprintf(os.Stderr, "[fec-client-stages] dial_ms=%d header_ms=%d send_blocks_ms=%d arq_drain_ms=%d tx_stats_ms=%d post_wait_ms=%d keep_stop_ms=%d total_ms=%d\n",
		dialDur.Milliseconds(), hdrDur.Milliseconds(), sendBlocksDur.Milliseconds(), arqDrainDur.Milliseconds(), txStatsDur.Milliseconds(), postWaitDur.Milliseconds(), keepStopDur.Milliseconds(), time.Since(startTotal).Milliseconds())
	if enableQuicStats {
		fmt.Fprintln(os.Stderr, quicStats.Format("[fec-client-quic-stats]"))
	}
	return nil
}

// ServerRecvFile listens for a connection on ln, receives the file and writes to outDir.
// If the sender provided a non-zero SHA256 in the header, it is verified during finalize.
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
	recvStart := time.Now()

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
		// Client-controlled receiver soft deadline (DDL_MS) carried in the header.
		// This controls ARQ NACK timing for seen blocks (idle-from-lastSymAt).
		prevSoft := rx.SoftDDL
		if hdr.RxDDLMS > 0 {
			rx.SoftDDL = time.Duration(hdr.RxDDLMS) * time.Millisecond
		}
		if hdr.MaxARQAttempts > 0 {
			rx.MaxARQAttempts = int(hdr.MaxARQAttempts)
		}
		devLogRxDDL("server_softddl_before=%s hdr_ddl_ms=%d server_softddl_after=%s", prevSoft, hdr.RxDDLMS, rx.SoftDDL)
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
				w := rxm.delivered.Load()
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
		lastDelivered := rxm.delivered.Load()
		lastDeliverChange := time.Now()
		lastDgrams := rcvDgrams
		lastDgramChange := time.Now()
		// Make inactivity more tolerant for high-RTT/high-redundancy runs.
		inactivity := 3 * time.Second
		if rx.DecodeDDL > 0 {
			if d := 2 * rx.DecodeDDL; d > inactivity {
				inactivity = d
			}
		}
		if inactivity < 6*time.Second {
			inactivity = 6 * time.Second
		}
		for {
			if rxm.delivered.Load() >= hdr.FileSize {
				return
			}
			select {
			case <-rxm.doneCh:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				w := rxm.delivered.Load()
				if w != lastDelivered {
					lastDelivered = w
					lastDeliverChange = time.Now()
				}
				if rcvDgrams != lastDgrams {
					lastDgrams = rcvDgrams
					lastDgramChange = time.Now()
				}
				if time.Since(lastDeliverChange) > inactivity && time.Since(lastDgramChange) > inactivity {
					return
				}
			}
		}
	}()
	// DATAGRAM receiver
	go func() {
		for {
			select {
			case <-rxm.doneCh:
				return
			default:
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
				fmt.Fprintf(os.Stderr, "[server-progress] dgrams=%d written=%d/%d\n", rcvDgrams, rxm.delivered.Load(), hdr.FileSize)
			}
			var fh fecwire.FECHeader
			if !fh.UnmarshalBinary(b) || fh.Scheme != fecwire.SchemeRaptorQ {
				continue
			}
			if int(fh.PayloadLen) > len(b)-fecwire.HeaderLen {
				continue
			}
			data := b[fecwire.HeaderLen : fecwire.HeaderLen+int(fh.PayloadLen)]
			// IMPORTANT: Always decode blocks as if they were full-sized (K*L), even for the last
			// partial block. The sender pads source symbols beyond EOF with zeros, and the decoder
			// must see the same effective K to interpret ESIs consistently (otherwise late-ESI
			// padded source symbols can be misinterpreted as repair symbols and corrupt decode).
			maxBlock := int(fh.K) * int(hdr.ChunkL)
			_ = rxm.ingest(fh.BlockID, int(fh.SymID), int(fh.N), int(fh.K), int(hdr.ChunkL), data, maxBlock)
		}
	}()
	// Uni stream receiver (symbols framed as {FEC header}{payload})
	go func() {
		for {
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
					prefix := make([]byte, 4)
					if _, err := io.ReadFull(us, prefix); err != nil {
						return
					}
					// Sender stats stream: {magic(4)}{ver(1)}{tx_source(u64)}{tx_repair(u64)}
					if string(prefix) == txStatsMagic {
						st := make([]byte, 1+8+8)
						if _, err := io.ReadFull(us, st); err != nil {
							return
						}
						if len(st) >= 1 && int(st[0]) == txStatsVersion {
							src := int64(binary.LittleEndian.Uint64(st[1:9]))
							rep := int64(binary.LittleEndian.Uint64(st[9:17]))
							if rxm != nil && rxm.met != nil {
								rxm.met.SetTxSymbolCounts(src, rep)
							}
						}
						return
					}
					// If transfer is already complete, ignore any late symbol streams.
					select {
					case <-rxm.doneCh:
						return
					default:
					}
					// Otherwise: treat as a symbol record. prefix is the start of the FEC header.
					hdrb := make([]byte, fecwire.HeaderLen)
					copy(hdrb[:4], prefix)
					if _, err := io.ReadFull(us, hdrb[4:]); err != nil {
						return
					}
					var fh fecwire.FECHeader
					if !fh.UnmarshalBinary(hdrb) || fh.Scheme != fecwire.SchemeRaptorQ {
						return
					}
					plen := int(fh.PayloadLen)
					if plen < 0 || plen > 1<<20 {
						return
					}
					buf := make([]byte, plen)
					if _, err := io.ReadFull(us, buf); err != nil {
						return
					}
					// See datagram path above: keep block decode size fixed to K*L.
					maxBlock := int(fh.K) * int(hdr.ChunkL)
					_ = rxm.ingest(fh.BlockID, int(fh.SymID), int(fh.N), int(fh.K), int(hdr.ChunkL), buf, maxBlock)
				}
			}(s)
		}
	}()
	// wait for reception to complete
	<-doneCh
	// E2E completion time: transport + retransmissions + decode only.
	// IMPORTANT: log this BEFORE closeAndFinalize(), which may include disk IO (and optional SHA verification).
	e2eDur := time.Since(recvStart)
	e2eOk := 0
	if rxm != nil && rxm.delivered.Load() >= hdr.FileSize {
		e2eOk = 1
	}
	if e2eDur < 0 {
		e2eDur = 0
	}
	var writtenNow uint64
	if rxm != nil {
		writtenNow = rxm.delivered.Load()
	}
	fmt.Fprintf(os.Stderr, "[server-e2e] e2e_ms=%d ok=%d written=%d/%d\n", e2eDur.Milliseconds(), e2eOk, writtenNow, hdr.FileSize)
	// Server->client DONE ACK: best-effort notify sender that receive/decode finished.
	// Use the same buffered control stream writer to avoid interleaving with ACK/NACK.
	if rxm != nil && rxm.ctrlOut != nil {
		var b bytes.Buffer
		_ = writeDone(&b, DoneFile{FileID: 0, Written: writtenNow, Ok: uint8(e2eOk)})
		payload := b.Bytes()
		select {
		case rxm.ctrlOut <- payload:
			// ok
		default:
			// avoid blocking; we only need best-effort delivery
			select {
			case rxm.ctrlOut <- payload:
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	// Wait briefly for the client to report sender-side tx symbol counts (used for fec_overhead).
	// Without this grace period, the stats stream can arrive just after completion and be missed.
	if rxm != nil && rxm.met != nil {
		select {
		case <-rxm.met.TxStatsDone():
		case <-time.After(500 * time.Millisecond):
		}
	}
	cancelRx()
	close(progStop)
	finalPath, err := rxm.closeAndFinalize(hdr.SHA256)
	if err != nil {
		// Best-effort DONE ACK with ok=0 on failure.
		if rxm != nil && rxm.ctrlOut != nil {
			var b bytes.Buffer
			_ = writeDone(&b, DoneFile{FileID: 0, Written: writtenNow, Ok: 0})
			payload := b.Bytes()
			select {
			case rxm.ctrlOut <- payload:
			default:
			}
		}
		// On failure (e.g., SHA mismatch / residual erasures), still emit a best-effort observation
		// so external harnesses don't stall waiting for metrics.
		if rxm != nil && rxm.met != nil && !rx.DisableObservation {
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
		if rxm.met != nil && !rx.DisableObservation {
			obs := rxm.met.Snapshot(time.Now())
			obs.PrintJSON()
		}
	} else {
		fmt.Fprintf(os.Stderr, "[server-stats] dgrams=%d dur_s=%.3f mbps=%.2f -> %s\n", rcvDgrams, rdur, mbps2, finalPath)
	}
	if grace := doneFlushGrace(); grace > 0 {
		time.Sleep(grace)
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
			return devWrapConnTracer(NewECNConnTracer(ecnStats))
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
			return devWrapConnTracer(NewECNConnTracer(ecnStats))
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
	batch    int
	pending  int
}

func newPacer(interval time.Duration) *pacer {
	if interval <= 0 {
		return nil
	}
	return &pacer{interval: interval, batch: 1}
}

func (p *pacer) SetBatch(n int) {
	if p == nil {
		return
	}
	if n <= 0 {
		n = 1
	}
	p.mu.Lock()
	p.batch = n
	if p.pending >= p.batch {
		// Don't block here; just force the next AfterSend() to pace immediately.
		p.pending = p.batch
	}
	p.mu.Unlock()
}

// AfterSend should be called once per sent datagram. It applies pacing in batches.
func (p *pacer) AfterSend() {
	if p == nil {
		return
	}
	slots := 0
	p.mu.Lock()
	p.pending++
	if p.pending >= p.batch {
		slots = p.pending
		p.pending = 0
	}
	p.mu.Unlock()
	if slots > 0 {
		p.WaitN(slots)
	}
}

// WaitN reserves N pacing slots and blocks until the scheduled time.
func (p *pacer) WaitN(slots int) {
	if p == nil {
		return
	}
	if slots <= 0 {
		slots = 1
	}
	step := time.Duration(slots) * p.interval

	// Reserve the next slots and compute the due time.
	p.mu.Lock()
	due := p.nextDue
	now := time.Now()
	if due.IsZero() || now.After(due) {
		due = now.Add(step)
	} else {
		due = due.Add(step)
	}
	p.nextDue = due
	p.mu.Unlock()

	// Wait until due.
	if p.interval < 2*time.Millisecond {
		for time.Now().Before(due) {
		}
		return
	}
	for {
		rem := time.Until(due)
		if rem <= 0 {
			return
		}
		if rem > 5*time.Millisecond {
			time.Sleep(rem - 1*time.Millisecond)
			continue
		}
		if rem > 800*time.Microsecond {
			time.Sleep(rem - 400*time.Microsecond)
			continue
		}
		break
	}
	for time.Now().Before(due) {
	}
}

// Wait blocks until the next scheduled time, then advances the schedule by interval.
// It is safe for concurrent use; calls are serialized to maintain spacing across senders.
func (p *pacer) Wait() {
	if p == nil {
		return
	}
	p.WaitN(1)
}

// ListenAndServeLoopWithRX allows configuring the receiver options.
func ListenAndServeLoopWithRX(ctx context.Context, addr, alpn, outDir string, tlsConf *tls.Config, rx RXOptions, onStored func(string)) error {
	if tlsConf == nil {
		return errors.New("tlsConf required")
	}
	ecnStats := NewECNStats()
	ln, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			return devWrapConnTracer(logging.NewMultiplexedConnectionTracer(
				NewECNConnTracer(ecnStats),
				newServerSRTTTracer(),
			))
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
