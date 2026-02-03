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
	"runtime"
	"strconv"
	"strings"
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
	UseARQ         bool // enable ARQ control plane and on-demand repairs
	InitialRepairs int  // R0: additional repairs to send initially (defaults to N-K if N provided)
	WindowW        int  // max unfinished clusters in flight (0=unlimited)
	RStep          int  // repairs to append per repair round
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
	// DATAGRAM-only packets are not ACK-eliciting. Without occasional ACK-eliciting
	// frames (e.g. tiny STREAM writes), BBRv2 has weak ACK clocking and the sender
	// may underfill the bottleneck even on no-loss links.
	// Convention in our tooling: ackEvery=0 means "auto".
	if ackEvery <= 0 {
		ackEvery = 8
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
	// Sender-side loss observation (only used when ARQ / repair scheduling is enabled).
	// This receives callbacks from the QUIC stack when DATAGRAM frames are ACKed or declared lost.
	// We forward only (blockID, symID) metadata via a buffered channel.
	dgramEvtCh := make(chan dgramEvt, 262144)
	var dObs *datagramObserver
	if opts.UseARQ {
		dObs = &datagramObserver{ch: dgramEvtCh}
	}
	qconf := &quic.Config{
		// attach our ECN tracer to observe CE/ECT counts
		Tracer: func(ctx context.Context, p logging.Perspective, cid logging.ConnectionID) *logging.ConnectionTracer {
			return logging.NewMultiplexedConnectionTracer(
				NewECNConnTracer(ecnStats),
				NewCCDebugConnTracer(),
			)
		},
		EnableDatagrams: true,
		DatagramObserver: func() quic.DatagramObserver {
			// Avoid taking a dependency on ARQ in the QUIC core; just return the fecquic observer.
			if dObs == nil {
				return nil
			}
			return dObs
		}(),
		// Reliability under loss/RTT:
		// - Handshake can legitimately take multiple seconds under GE burst loss.
		// - A very small KeepAlivePeriod (e.g. 20ms) adds lots of extra packets,
		//   hurting short-flow goodput and inflating measured overhead.
		HandshakeIdleTimeout:           30 * time.Second,
		KeepAlivePeriod:                2 * time.Second,
		MaxIdleTimeout:                 90 * time.Second,
		InitialStreamReceiveWindow:     8 * 1024 * 1024,
		InitialConnectionReceiveWindow: 16 * 1024 * 1024,
	}
	t0 := time.Now()
	conn, err := quic.DialAddr(ctx, addr, tlsConf, qconf)
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
	var sendQFullCount int64
	var lastSendQFullLog time.Time
	var lastSendErrLog time.Time
	var sendErrLogCount int
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
	sendBlocksDone := make(chan struct{})
	// Reuse per-symbol buffers to reduce allocations / GC overhead.
	// Safe because SendDatagram / Stream.Write copy from the provided slice before returning.
	symBufPool := sync.Pool{New: func() any { return make([]byte, fecwire.HeaderLen+L) }}

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
		for {
			err := conn.SendDatagram(b)
			if err == nil {
				return nil
			}
			now := time.Now()
			// Avoid deadlocks: SendDatagram can block internally when the send queue is full.
			// The QUIC stack will return ErrDatagramSendQueueFull after a bounded wait.
			// Retry with ctx awareness instead of hanging forever.
			if errors.Is(err, quic.ErrDatagramSendQueueFull) {
				sendQFullCount++
				if lastSendQFullLog.IsZero() || now.Sub(lastSendQFullLog) >= 1*time.Second {
					lastSendQFullLog = now
					fmt.Fprintf(os.Stderr, "[client-sendq] full; sent_dgrams=%d\n", sentDgrams)
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(2 * time.Millisecond):
					continue
				}
			}
			var dtle *quic.DatagramTooLargeError
			if errors.As(err, &dtle) {
				dtleCount++
			}
			if sendErrLogCount < 16 && (lastSendErrLog.IsZero() || now.Sub(lastSendErrLog) >= 250*time.Millisecond) {
				lastSendErrLog = now
				sendErrLogCount++
				fmt.Fprintf(os.Stderr, "[client-send] err=%T %v\n", err, err)
			}
			return err
		}
	}

	// Live goodput printer
	liveStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		stallDumped := false
		lastProgressAt := time.Now()
		lastBytes := int64(-1)
		dumpOnStall := os.Getenv("QUIC_FEC_DUMP_ON_STALL") == "1"
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
				if b != lastBytes {
					lastBytes = b
					lastProgressAt = time.Now()
				} else if dumpOnStall && !stallDumped {
					select {
					case <-sendBlocksDone:
						// send loop finished; stalls here are expected (waiting for ACK/DONE)
					default:
						if time.Since(lastProgressAt) >= 2*time.Second {
							stallDumped = true
							buf := make([]byte, 1<<20)
							n := runtime.Stack(buf, true)
							fmt.Fprintf(os.Stderr, "[stall] no tx progress for %s; dumping stacks\n%s\n", time.Since(lastProgressAt).Truncate(time.Millisecond), string(buf[:n]))
						}
					}
				}
				mbps := (float64(b) * 8 / 1e6) / dur
				_, _, rx0, rx1, rxce, _ := ecnStats.Snapshot()
				fmt.Fprintf(os.Stderr, "[live-client] tx_bytes=%d mbps=%.2f ecn_rx: CE=%d, ECT0=%d, ECT1=%d\n", b, mbps, rxce, rx0, rx1)
			}
		}
	}()

	// Send symbols per block
	sendBlocksStart := time.Now()
	fmt.Fprintf(os.Stderr, "[sender-e2e] start_ns=%d\n", time.Now().UnixNano())
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
		blockBytes []byte              // padded to exactly K*L
		enc        *fec.RaptorQEncoder // lazily initialized when repairs are needed
		nextESI    int                 // next repair ESI to send (>=K)
		repairsOut int                 // how many repairs sent so far
		// repair scheduling guards
		sending      bool      // true while a repair batch is being appended
		lastRepairAt time.Time // last time we finished appending a repair batch
		nextRepairAt time.Time // next eligible time to append another repair batch (PTO-style)
		lastAckAt    time.Time // last time we observed a new ACK for this block (PTO based on ack-progress)
		armedAt      time.Time // time when we finished sending the initial codeword for this block
		// sender-side loss accounting (based on QUIC packet loss detection)
		totalSent  int
		acked      [256]bool
		lost       [256]bool
		ackedCount int
		lostCount  int
		pending    bool
		attempt    int // how many Rstep repair rounds we've appended
	}
	txMu := &sync.Mutex{}
	active := make(map[uint16]*blockTx)
	cond := sync.NewCond(txMu)

	// Sender-side repair requests (loss-driven, based on QUIC's default packetThreshold=3).
	// The receiver no longer sends NACK; it only sends a reliable ACK when a block decodes successfully.
	type repairReq struct {
		bid    uint16
		n      int
		reason string
	}
	repairReqCh := make(chan repairReq, 65536)
	// Debounce repair batches per block. Without this, bursty/spurious loss signals can
	// enqueue many back-to-back Rstep batches for the same block, inflating overhead.
	// Override with QUIC_FEC_ARQ_REPAIR_COOLDOWN_MS (0 disables cooldown).
	// Default is 0 because nextRepairAt (PTO-style gating) is the primary pacing mechanism.
	repairCooldown := time.Duration(0)
	if v := strings.TrimSpace(os.Getenv("QUIC_FEC_ARQ_REPAIR_COOLDOWN_MS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			if n <= 0 {
				repairCooldown = 0
			} else {
				repairCooldown = time.Duration(n) * time.Millisecond
			}
		}
	}
	// PTO-style repair pacing: mimic QUIC retransmission behavior.
	basePTO := 100 * time.Millisecond
	if rttStr := strings.TrimSpace(os.Getenv("RTT_MS")); rttStr != "" {
		if ms, err := strconv.Atoi(rttStr); err == nil && ms > 0 {
			// Approximate PTO as 2*RTT.
			basePTO = time.Duration(ms*2) * time.Millisecond
		}
	}
	if ptoStr := strings.TrimSpace(os.Getenv("QUIC_FEC_ARQ_PTO_MS")); ptoStr != "" {
		if ms, err := strconv.Atoi(ptoStr); err == nil {
			if ms <= 0 {
				basePTO = 0
			} else {
				basePTO = time.Duration(ms) * time.Millisecond
			}
		}
	}
	// Cap the burst size of a single repair batch.
	maxBatch := maxInt(8, maxInt(1, opts.RStep)*4)
	if s := strings.TrimSpace(os.Getenv("QUIC_FEC_ARQ_MAX_BATCH")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			maxBatch = n
		}
	}
	// Periodic scan tick for PTO-based repairs.
	// Default: disabled. Probing can inflate overhead under burst/GE loss.
	// Enable with QUIC_FEC_ARQ_SCAN_TICK_MS (e.g. 10).
	scanTick := time.Duration(0)
	if s := strings.TrimSpace(os.Getenv("QUIC_FEC_ARQ_SCAN_TICK_MS")); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			if n <= 0 {
				scanTick = 0
			} else {
				scanTick = time.Duration(n) * time.Millisecond
			}
		}
	}
	computeDeficit := func(bt *blockTx) int {
		maxDeliverable := bt.totalSent - bt.lostCount
		if bt.K-maxDeliverable <= 0 {
			return 0
		}
		return bt.K - maxDeliverable
	}
	computeBatchForLoss := func(bt *blockTx) int {
		// Always use RStep-sized batches (capped by deficit) to avoid over-repair bursts.
		r := opts.RStep
		if r <= 0 {
			r = 4
		}
		def := computeDeficit(bt)
		if def <= 0 {
			return 0
		}
		if def < r {
			r = def
		}
		if r < 1 {
			r = 1
		}
		return minInt(maxBatch, r)
	}
	computeBatchForPTO := func(bt *blockTx) int {
		// Probe with RStep (or smaller if we can infer we're close), but always send at least 1.
		r := opts.RStep
		if r <= 0 {
			r = 4
		}
		missing := bt.K - bt.ackedCount
		if missing < 1 {
			missing = 1
		}
		if missing < r {
			r = missing
		}
		if r < 1 {
			r = 1
		}
		return minInt(maxBatch, r)
	}
	// Tail rescue: for tail losses where QUIC doesn't quickly declare DATAGRAMs lost.
	// Default: disabled (can inflate overhead under GE). Enable with QUIC_FEC_ARQ_TAIL_RESCUE_MS.
	tailRescue := time.Duration(0)
	if s := strings.TrimSpace(os.Getenv("QUIC_FEC_ARQ_TAIL_RESCUE_MS")); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			if n <= 0 {
				tailRescue = 0
			} else {
				tailRescue = time.Duration(n) * time.Millisecond
			}
		}
	}
	if opts.UseARQ {
		fmt.Fprintf(os.Stderr, "[arq-conf] use=1 base_pto_ms=%d scan_tick_ms=%d tail_rescue_ms=%d rstep=%d max_batch=%d\n",
			basePTO.Milliseconds(), scanTick.Milliseconds(), tailRescue.Milliseconds(), opts.RStep, maxBatch)
		// PTO-style repair timer: if a block is still missing symbols after PTO, send another batch
		// even if no new loss callbacks arrive.
		if scanTick > 0 {
			go func() {
				t := time.NewTicker(scanTick)
				defer t.Stop()
				lastHB := time.Time{}
				for {
					select {
					case <-ctx.Done():
						return
					case <-t.C:
						now := time.Now()
						// heartbeat / debug snapshot (rate-limited)
						var hbLine string
						txMu.Lock()
						if lastHB.IsZero() || now.Sub(lastHB) >= 1*time.Second {
							activeN := len(active)
							pendingN := 0
							armedZero := 0
							oldestMs := int64(0)
							for _, bt := range active {
								if bt == nil {
									continue
								}
								if bt.pending {
									pendingN++
								}
								if bt.armedAt.IsZero() {
									armedZero++
									continue
								}
								ageMs := now.Sub(bt.armedAt).Milliseconds()
								if ageMs > oldestMs {
									oldestMs = ageMs
								}
							}
							hbLine = fmt.Sprintf("[arq-scan] active=%d pending=%d armed_zero=%d oldest_ms=%d\n", activeN, pendingN, armedZero, oldestMs)
							lastHB = now
						}
						for bid, bt := range active {
							if bt == nil || bt.pending || bt.sending {
								continue
							}
							if basePTO <= 0 || bt.armedAt.IsZero() {
								continue
							}
							// Don't probe immediately after the initial codeword.
							// Loss-driven repairs are handled by the dgram ACK/loss handler.
							if now.Sub(bt.armedAt) < basePTO {
								continue
							}
							// Only fire when the per-block timer expires.
							if !bt.nextRepairAt.IsZero() && now.Before(bt.nextRepairAt) {
								continue
							}
							// Determine whether we should send PTO-based repairs:
							// - If QUIC already declared loss for this block (hard deficit), recover.
							// - If we've already started repairing (attempt>0), continue probing.
							// - Else, tail-rescue after a longer delay *even if QUIC ACKed K packets*.
							//   QUIC ACK only means the packet arrived, not that the receiver admitted
							//   the symbol into its decode buffer.
							needHard := computeDeficit(bt) > 0
							needRepair := false
							if needHard {
								needRepair = true
							} else if bt.attempt > 0 {
								// If loss deficit is already covered and QUIC has ACKed >=K symbols,
								// the receiver likely has enough to decode and we're just waiting on
								// the success ACK. Probing too frequently here inflates overhead under GE.
								if bt.ackedCount >= bt.K {
									if tailRescue > 0 && !bt.lastRepairAt.IsZero() && now.Sub(bt.lastRepairAt) >= tailRescue {
										needRepair = true
									}
								} else {
									needRepair = true
								}
							} else if tailRescue > 0 && now.Sub(bt.armedAt) >= tailRescue {
								needRepair = true
							}
							canRepair := opts.MaxAttempts <= 0 || bt.attempt < opts.MaxAttempts
							if !needRepair || !canRepair {
								continue
							}
							if repairCooldown > 0 && !bt.lastRepairAt.IsZero() && now.Sub(bt.lastRepairAt) < repairCooldown {
								continue
							}
							bt.pending = true
							n := computeBatchForPTO(bt)
							select {
							case repairReqCh <- repairReq{bid: bid, n: n, reason: "pto"}:
								// Breadcrumb for diagnosing "no repairs sent" stalls.
								fmt.Fprintf(os.Stderr, "[arq-scan] enqueue block=%d n=%d hard=%v attempt=%d age_ms=%d\n",
									bid, n, needHard, bt.attempt, now.Sub(bt.armedAt).Milliseconds())
							default:
								// Don't wedge the block if the queue is temporarily full.
								bt.pending = false
							}
						}
						txMu.Unlock()
						if hbLine != "" {
							fmt.Fprint(os.Stderr, hbLine)
						}
					}
				}
			}()
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case e := <-dgramEvtCh:
					if e.typ != dgramEvtAck && e.typ != dgramEvtLost {
						continue
					}
					txMu.Lock()
					bt := active[e.blockID]
					if bt == nil {
						txMu.Unlock()
						continue
					}
					// Don't schedule repairs before the initial codeword for this block is fully sent.
					// Otherwise repairs can overlap with initial sending and contend in the encoder.
					armed := !bt.armedAt.IsZero()
					idx := int(e.symID)
					if idx >= 0 && idx < len(bt.acked) {
						if e.typ == dgramEvtAck {
							if !bt.acked[idx] {
								bt.acked[idx] = true
								bt.ackedCount++
								bt.lastAckAt = time.Now()
							}
							// ACK overrides loss (QUIC may declare loss before a later ACK arrives).
							if bt.lost[idx] {
								bt.lost[idx] = false
								if bt.lostCount > 0 {
									bt.lostCount--
								}
							}
						} else {
							// Ignore loss if already ACKed.
							if !bt.acked[idx] && !bt.lost[idx] {
								bt.lost[idx] = true
								bt.lostCount++
							}
						}
					}
					// If even in the best case (all non-lost packets arrive) we can't reach K symbols,
					// append repairs (PTO-style, debounced per block).
					needRepair := armed && computeDeficit(bt) > 0
					canRepair := opts.MaxAttempts <= 0 || bt.attempt < opts.MaxAttempts
					if needRepair && canRepair && !bt.pending && !bt.sending {
						now := time.Now()
						if !bt.nextRepairAt.IsZero() && now.Before(bt.nextRepairAt) {
							// too early to send another batch for this block
							txMu.Unlock()
							continue
						}
						if repairCooldown > 0 && !bt.lastRepairAt.IsZero() && now.Sub(bt.lastRepairAt) < repairCooldown {
							txMu.Unlock()
							continue
						}
						bt.pending = true
						n := computeBatchForLoss(bt)
						if n <= 0 {
							bt.pending = false
							txMu.Unlock()
							continue
						}
						select {
						case repairReqCh <- repairReq{bid: e.blockID, n: n, reason: "loss"}:
						default:
							// Don't wedge the block if the queue is temporarily full.
							bt.pending = false
						}
					}
					txMu.Unlock()
				}
			}
		}()
	}

	// DONE ACK (server->client) via control uni-stream.
	// Enabled by default; disable with QUIC_FEC_WAIT_DONE=0.
	waitDone := os.Getenv("QUIC_FEC_WAIT_DONE") != "0"
	doneMsgCh := make(chan DoneFile, 1)
	var doneSeen sync.Once
	var doneObserved *DoneFile

	// Control reader: accept server control uni stream(s) and react to ACK/DONE.
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
					case arqMsgACK:
						if !opts.UseARQ {
							continue
						}
						a := msg.(AckSuccess)
						bid := uint16(a.ClusterID)
						var kickBid *uint16
						kickN := 0
						txMu.Lock()
						delete(active, bid)
						// If later blocks succeed but an earlier block is still pending, kick the earliest one.
						var minPending uint16
						found := false
						for id := range active {
							if id < bid {
								if !found || id < minPending {
									minPending = id
									found = true
								}
							}
						}
						if found {
							bt := active[minPending]
							if bt != nil && !bt.pending && !bt.sending {
								now := time.Now()
								if (!bt.nextRepairAt.IsZero() && now.Before(bt.nextRepairAt)) || (repairCooldown > 0 && !bt.lastRepairAt.IsZero() && now.Sub(bt.lastRepairAt) < repairCooldown) {
									// not eligible yet
								} else {
									bt.pending = true
									kickBid = &minPending
									kickN = computeBatchForPTO(bt)
								}
							}
						}
						txMu.Unlock()
						if kickBid != nil {
							select {
							case repairReqCh <- repairReq{bid: *kickBid, n: kickN, reason: "out_of_order"}:
							default:
							}
						}
						cond.Broadcast()
					}
				}
			}(us)
		}
	}()

	// Sender-side repair appender: send fresh repair symbols for a block.
	// Bounded by maxBatch and ESI space (0..255).
	sendRepairs := func(bid uint16, n int, reason string) {
		if !opts.UseARQ {
			return
		}
		if n <= 0 {
			n = 1
		}
		if n > maxBatch {
			n = maxBatch
		}
		// Mark the block as actively sending repairs so we don't enqueue another batch
		// mid-flight due to loss callbacks.
		now := time.Now()
		txMu.Lock()
		bt0 := active[bid]
		if bt0 == nil {
			txMu.Unlock()
			return
		}
		// Clear pending on batch start.
		bt0.pending = false
		bt0.sending = true
		if basePTO > 0 {
			cooldown := basePTO
			// For FEC repairs, waiting a full PTO between batches is overly conservative.
			// Use a shorter cooldown to recover GE bursts faster.
			if reason != "window_full" {
				short := basePTO / 4
				if short < 20*time.Millisecond {
					short = 20 * time.Millisecond
				}
				if short < cooldown {
					cooldown = short
				}
			}
			// Only the window-pressure kick should bypass the usual PTO-style spacing.
			// Being too aggressive on ordinary loss callbacks can inflate repair overhead.
			if reason == "window_full" {
				if cooldown > 10*time.Millisecond {
					cooldown = 10 * time.Millisecond
				}
			}
			bt0.nextRepairAt = now.Add(cooldown)
		} else {
			bt0.nextRepairAt = time.Time{}
		}
		txMu.Unlock()
		defer func() {
			txMu.Lock()
			if bt := active[bid]; bt != nil {
				bt.sending = false
			}
			txMu.Unlock()
		}()

		sentAny := 0
		for i := 0; i < n; i++ {
			txMu.Lock()
			bt := active[bid]
			if bt == nil {
				txMu.Unlock()
				break
			}
			// Optional attempt cap (each repair batch counts as one attempt).
			if opts.MaxAttempts > 0 && bt.attempt >= opts.MaxAttempts {
				delete(active, bid)
				txMu.Unlock()
				cond.Broadcast()
				fmt.Fprintf(os.Stderr, "[arq] giveup block=%d at attempt=%d (max=%d)\n", bid, bt.attempt, opts.MaxAttempts)
				return
			}
			esi := bt.nextESI
			if esi > 255 {
				txMu.Unlock()
				break
			}
			enc := bt.enc
			blockBytes := bt.blockBytes
			L := bt.L
			K := bt.K
			repairsOut := bt.repairsOut
			txMu.Unlock()

			if enc == nil {
				// Lazily initialize encoder only if we actually need to generate repairs.
				enc0, encErr := fec.NewRaptorQEncoder(blockBytes, K, L)
				if encErr != nil {
					sendErrs++
					continue
				}
				txMu.Lock()
				if bt2 := active[bid]; bt2 != nil {
					if bt2.enc == nil {
						bt2.enc = enc0
					}
					enc = bt2.enc
				}
				txMu.Unlock()
				if enc == nil {
					// Block was removed while initializing.
					break
				}
			}

			// IMPORTANT: never call GenSymbol while holding txMu.
			// Under loss, repair scheduling can overlap with send-path bookkeeping.
			// If GenSymbol blocks (or contends internally), holding txMu here can deadlock
			// the main sender which needs txMu to update counters.
			payload := enc.GenSymbol(uint32(esi))

			b := symBufPool.Get().([]byte)
			pay := b[fecwire.HeaderLen:]
			if len(payload) == L {
				copy(pay, payload)
			} else {
				clear(pay)
				copy(pay, payload)
			}
			advN := minInt(255, K+repairsOut+1)
			h := fecwire.FECHeader{
				Version:    1,
				Scheme:     fecwire.SchemeRaptorQ,
				BlockID:    bid,
				N:          uint8(advN),
				K:          uint8(K),
				SymID:      uint8(esi),
				Flags:      uint8(minInt(255, n)),
				PayloadLen: uint32(L),
			}
			h.MarshalBinary(b[:fecwire.HeaderLen])
			err := sendSymbol(b)
			symBufPool.Put(b)
			if err == nil {
				sentDgrams++
				sentBytes += int64(len(b))
				totalSymbols++
				totalRepairs++
				sentAny++
				txMu.Lock()
				if bt2 := active[bid]; bt2 != nil {
					bt2.nextESI++
					bt2.repairsOut++
					bt2.totalSent++
				}
				txMu.Unlock()
				if pc != nil {
					pc.AfterSend()
				}
			} else {
				sendErrs++
			}
		}
		if sentAny > 0 {
			totalAttempts++
			txMu.Lock()
			if bt := active[bid]; bt != nil {
				bt.attempt++
				bt.lastRepairAt = time.Now()
				// Debug breadcrumb.
				fmt.Fprintf(os.Stderr, "[arq] repair block=%d round=%d sent=%d reason=%s\n", bid, bt.attempt, sentAny, reason)
			}
			txMu.Unlock()
		}
	}

	// Dedicated repair worker: single consumer of repairReqCh.
	// This prevents deadlocks / races from having multiple goroutines call sendRepairs.
	if opts.UseARQ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case req := <-repairReqCh:
					sendRepairs(req.bid, req.n, req.reason)
				}
			}
		}()
	}

	for {
		// Read a full padded block of size K*L. For the last partial block, the tail is already zero.
		blockBytes := make([]byte, K*L)
		n, err := io.ReadFull(f, blockBytes)
		if err == io.EOF {
			if n == 0 {
				break
			}
		} else if err == io.ErrUnexpectedEOF {
			// last partial block; keep n
		} else if err != nil {
			return err
		}
		// Enforce ARQ window to limit unfinished clusters.
		// If a timeout is hit once, disable further gating to avoid cumulative stalls.
		if opts.UseARQ && opts.WindowW > 0 && !arqWindowDisabled {
			// Under GE burst loss, strict window gating can cause sender stalls and
			// trigger overly aggressive window-pressure repairs. Keep this wait short.
			deadline := time.Now().Add(50 * time.Millisecond)
			for {
				txMu.Lock()
				nActive := len(active)
				if nActive < opts.WindowW {
					txMu.Unlock()
					break
				}
				txMu.Unlock()
				if time.Now().After(deadline) {
					fmt.Fprintf(os.Stderr, "[arq] window wait timeout; proceeding n=%d W=%d; disabling window gating\n", nActive, opts.WindowW)
					arqWindowDisabled = true
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
		}
		// Lazily initialize a RaptorQ encoder only if we actually need to send any
		// repair symbols (initial repairs or ARQ later). This significantly improves
		// goodput in the common case where the systematic codeword is sufficient.
		var enc *fec.RaptorQEncoder
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
		if initN > K {
			tEnc := time.Now()
			enc0, encErr := fec.NewRaptorQEncoder(blockBytes, K, L)
			if encErr != nil {
				return encErr
			}
			enc = enc0
			encTime += time.Since(tEnc)
		}
		// attempt counts how many repair rounds we already appended for this block.
		bt := &blockTx{K: K, L: L, blockBytes: blockBytes, enc: enc, nextESI: initN, repairsOut: maxInt(0, initN-K), attempt: 0}
		txMu.Lock()
		active[uint16(blockID)] = bt
		txMu.Unlock()
		// Emit initial symbols 0..initN-1
		for esi := 0; esi < initN; esi++ {
			b := symBufPool.Get().([]byte)
			pay := b[fecwire.HeaderLen:]
			// Systematic source symbols are just L-byte chunks of the padded block.
			if esi < K {
				start := esi * L
				copy(pay, blockBytes[start:start+L])
			} else {
				// Repair symbol. Ensure encoder exists.
				if enc == nil {
					enc0, encErr := fec.NewRaptorQEncoder(blockBytes, K, L)
					if encErr != nil {
						symBufPool.Put(b)
						return encErr
					}
					enc = enc0
					// Note: encTime is best-effort diagnostics; only updated from the send loop.
				}
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
				K:          uint8(K),
				SymID:      uint8(esi),
				Flags:      uint8(opts.RStep),
				PayloadLen: uint32(L),
			}
			h.MarshalBinary(b[:fecwire.HeaderLen])
			if opts.WarnDgramSize > 0 && len(b) > opts.WarnDgramSize {
				fmt.Printf("warn: datagram size %d exceeds threshold %d; consider reducing L or header size\n", len(b), opts.WarnDgramSize)
				opts.WarnDgramSize = 0 // warn once
			}
			dropped := rng != nil && rng.Float64() < opts.DropProb
			if dropped {
				// simulate sender drop
				symBufPool.Put(b)
			} else {
				tSend := time.Now()
				if err := sendSymbol(b); err != nil {
					sendErrs++
					if opts.Transport == "stream" {
						symBufPool.Put(b)
						return err
					}
					// For datagrams, attempt a single retry since packet size can shrink temporarily.
					if err2 := sendSymbol(b); err2 == nil {
						sentDgrams++
						sentBytes += int64(len(b))
						txMu.Lock()
						bt.totalSent++
						txMu.Unlock()
					} else {
						symBufPool.Put(b)
						// Don't spin forever when the QUIC stack returns a persistent error.
						return err2
					}
				} else {
					sentDgrams++
					sentBytes += int64(len(b))
					txMu.Lock()
					bt.totalSent++
					txMu.Unlock()
				}
				symBufPool.Put(b)
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
				pc.AfterSend()
			}
		}
		// Publish repair counters for this block after the initial emission.
		txMu.Lock()
		bt.nextESI = initN
		bt.repairsOut = maxInt(0, initN-K)
		bt.enc = enc
		txMu.Unlock()
		// Arm the PTO timer for this block only after we finished emitting the initial codeword.
		// This avoids sending repairs immediately just because ACKs haven't arrived yet.
		if opts.UseARQ && basePTO > 0 {
			now := time.Now()
			txMu.Lock()
			bt.armedAt = now
			bt.lastAckAt = now
			bt.nextRepairAt = time.Time{}
			txMu.Unlock()
		}
		blockID++
		if n < K*L { // done
			break
		}
		if opts.BlockPause > 0 {
			time.Sleep(opts.BlockPause)
		}
	}
	close(sendBlocksDone)
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
		// IMPORTANT: if we already received a receiver DONE(ok=1), stop draining early.
		// This avoids unstable tail waits due to delayed / lost per-block ACK control messages.
		for time.Now().Before(deadline) {
			doneOk := false
			if waitDone && doneObserved == nil {
				select {
				case d := <-doneMsgCh:
					dc := d
					doneObserved = &dc
					if d.Ok == 1 {
						fmt.Fprintf(os.Stderr, "[fec-client-done] early_ok=1; ending arq_drain\n")
						doneOk = true
					}
				default:
				}
			}
			if doneOk {
				break
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
		if doneObserved != nil {
			d := *doneObserved
			fmt.Fprintf(os.Stderr, "[fec-client-done] wait_ms=%d ok=%d written=%d cached=1\n", time.Since(t0).Milliseconds(), d.Ok, d.Written)
		} else {
			select {
			case d := <-doneMsgCh:
				dc := d
				doneObserved = &dc
				fmt.Fprintf(os.Stderr, "[fec-client-done] wait_ms=%d ok=%d written=%d\n", time.Since(t0).Milliseconds(), d.Ok, d.Written)
			case <-ctx.Done():
				return ctx.Err()
			}
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
	if sendQFullCount > 0 {
		fmt.Fprintf(os.Stderr, "[client-sendq] full_hits=%d\n", sendQFullCount)
	}
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
	// open a control uni stream to client for ACK/DONE
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
					if plen <= 0 || plen > 1<<20 {
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
	fmt.Fprintf(os.Stderr, "[receiver-e2e] end_ns=%d ok=%d written=%d/%d\n", time.Now().UnixNano(), e2eOk, writtenNow, hdr.FileSize)
	// Server->client DONE ACK: best-effort notify sender that receive/decode finished.
	// Use the same buffered control stream writer to avoid interleaving with ACK/DONE.
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
	// For very small intervals, avoid pure busy-spinning: it can monopolize a CPU
	// core and starve QUIC's send/receive loops under loss.
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
		if rem > 150*time.Microsecond {
			time.Sleep(rem - 75*time.Microsecond)
			continue
		}
		break
	}
	for time.Now().Before(due) {
		// yield
		time.Sleep(0)
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
