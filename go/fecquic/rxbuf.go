package fecquic

import (
	bytespkg "bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/fec"
)

// RXOptions configures the receiver buffer and scheduler.
type RXOptions struct {
	BudgetBytes int           // total bytes for buffered symbols (default 10MB)
	DecodeDDL   time.Duration // receiver decode/check pacing (default 25ms)
	SoftDDL     time.Duration // receiver ARQ soft deadline (default 25ms)
	Workers     int           // decode workers (default numCPU)

	// OutPath, if set, writes the received file to this exact path.
	// A temporary file is written at OutPath+".part" and renamed on finalize.
	// If empty, the receiver writes to outDir/<baseName>.recv.
	OutPath string

	// DisableObservation disables emitting the final "[rl-observation]" JSON line.
	// This only affects logging, not metric collection.
	DisableObservation bool
}

func (o *RXOptions) setDefaults() {
	if o.BudgetBytes <= 0 {
		o.BudgetBytes = 64 * 1024 * 1024
	}
	if o.DecodeDDL <= 0 {
		o.DecodeDDL = 25 * time.Millisecond
	}
	if o.SoftDDL <= 0 {
		o.SoftDDL = 25 * time.Millisecond
	}
	if o.Workers <= 0 {
		o.Workers = 1 // keep simple; can tune later
	}
}

// writeTask represents a file write at a given offset.
type writeTask struct {
	off  int64
	data []byte
}

// rxBlock holds per-block state.
type rxBlock struct {
	id       uint32
	t0       time.Time
	K, N, L  int
	dataSize int // exact bytes for this block (last block may be partial)

	dec     *fec.RaptorQDecoder
	decMu   sync.Mutex // guards decoder AddSymbol/Decode; decoder is not goroutine-safe
	queued  bool
	done    bool
	attempt int       // ARQ attempt index
	nextDDL time.Time // next DDL fire time
	// store received symbols by ESI to avoid duplicates and allow release
	syms map[int][]byte
	// Fast path for systematic source symbols (ESI < K): write directly into a block buffer
	// to avoid per-symbol allocations and map overhead on low/no-loss links.
	srcBuf       []byte
	srcSeen      []bool
	srcSeenCount int
	// metrics timestamps
	firstSeen time.Time
	lastSymAt time.Time // last time we observed any symbol for this block (unique or duplicate)
	// decodeFailed is set when the decoder returns not-ok even though we may have
	// rx_unique>=K. This can happen due to linear dependence / rank deficiency.
	// In that case, the scheduler should keep NACKing for extra repairs.
	decodeFailed           bool
	lastDecodeFailAt       time.Time
	lastDecodeFailRxUnique int
	// ARQ de-bounce state
	lastNackAt       time.Time
	lastNackRxUnique int
	nackBackoff      time.Duration
	// nackWaitUntil is the earliest time we should allow the next NACK after
	// sending one, even if a few innovative repairs arrive in the meantime.
	// This preserves the intended softDDL + RTT-derived recovery wait.
	nackWaitUntil  time.Time
	unseenNackSent bool
}

// rxManager owns memory accounting, blocks, decode and write queues.
type rxManager struct {
	// config
	budget int
	ddl    time.Duration
	// softDDL is the soft-deadline for seen blocks: if a seen block has a deficit and
	// we haven't observed any symbol for that block for softDDL, we trigger a NACK.
	// This is measured from lastSymAt and is refreshed on every symbol arrival.
	softDDL time.Duration

	// file params
	fileSize uint64
	K, L     int
	outDir   string
	baseName string
	// totalBlocks is computed once K is known: ceil(fileSize / (K*L))
	totalBlocks int

	// state
	mu    sync.Mutex
	inUse atomic.Int64
	// blockSpan is the base block size in bytes for file offsets: baseK*L.
	// It is set when the first symbol arrives (when m.K becomes known).
	blockSpan atomic.Int64
	blocks    map[uint32]*rxBlock
	// completed remembers blocks that have already been fully decoded and written,
	// so late-arriving symbols for those blocks are ignored instead of recreating state.
	completed map[uint32]struct{}

	// queues
	decodeQ chan *rxBlock
	writeQ  chan writeTask
	stopCh  chan struct{}
	// wait groups: separate writer from decoders/scheduler
	wg    sync.WaitGroup // writer
	wgDec sync.WaitGroup // decoders + DDL scheduler

	// writer
	out     *os.File
	tmpPath string
	written atomic.Uint64
	// delivered counts bytes that are decoded / assembled and enqueued to the writer.
	// This excludes disk IO time and is used for E2E completion timing.
	delivered atomic.Uint64
	doneCh    chan struct{}
	doneOnce  sync.Once

	// metrics
	decBlocks    atomic.Int64
	decTimeTotal atomic.Int64 // ms
	dropsRepairs atomic.Int64

	// ARQ control (optional)
	ctrlW    io.Writer   // underlying stream
	ctrlOut  chan []byte // buffered queue to dedicated writer
	ctrlWG   sync.WaitGroup
	ctrlDead atomic.Bool
	// server metrics aggregator
	met *serverMetrics
	// first arrival timestamp (for missing-block ARQ heuristics)
	t0First time.Time
	// lastRxAt stores the unix nano timestamp of the last received symbol (including duplicates).
	// Used to avoid sending preemptive NACKs for unseen blocks while traffic is still flowing.
	lastRxAt atomic.Int64

	// tracking for missing blocks to NACK
	minSeen int  // first seen block id
	maxSeen int  // max seen block id
	seeded  bool // placeholders pre-created for all blocks when K known
}

func newRXManager(fileSize uint64, K, L int, outDir, baseName string, rx RXOptions) (*rxManager, error) {
	rx.setDefaults()
	if rx.OutPath != "" {
		outDir = filepath.Dir(rx.OutPath)
		baseName = filepath.Base(rx.OutPath)
		// Avoid accidental writes to root when OutPath has no directory component.
		if outDir == "" || outDir == "." {
			outDir = "."
		}
	}
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	m := &rxManager{
		budget:    rx.BudgetBytes,
		ddl:       rx.DecodeDDL,
		softDDL:   rx.SoftDDL,
		fileSize:  fileSize,
		K:         K,
		L:         L,
		outDir:    outDir,
		baseName:  baseName,
		blocks:    make(map[uint32]*rxBlock),
		completed: make(map[uint32]struct{}),
		decodeQ:   make(chan *rxBlock, 1024),
		writeQ:    make(chan writeTask, 8192),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		minSeen:   -1,
		maxSeen:   -1,
	}
	// softDDL is configured via rx.SoftDDL (typically from the client-provided header).
	if rx.OutPath != "" {
		m.tmpPath = filepath.Join(outDir, baseName+".part")
	} else {
		finalBase := baseName
		if finalBase == "" {
			finalBase = "qfec_recv.bin"
		}
		finalBase += ".recv"
		m.tmpPath = filepath.Join(outDir, finalBase+".part")
	}
	out, err := os.Create(m.tmpPath)
	if err != nil {
		return nil, err
	}
	if err := out.Truncate(int64(fileSize)); err != nil {
		_ = out.Close()
		return nil, err
	}
	m.out = out
	// init metrics aggregator
	m.met = newServerMetrics(int(fileSize))
	return m, nil
}

func (m *rxManager) noteDelivered(off int64, n int) {
	if m == nil {
		return
	}
	if n <= 0 {
		return
	}
	if off < 0 {
		return
	}
	max := int64(m.fileSize) - off
	if max <= 0 {
		return
	}
	if int64(n) > max {
		n = int(max)
	}
	m.delivered.Add(uint64(n))
	if m.delivered.Load() >= m.fileSize {
		m.doneOnce.Do(func() { close(m.doneCh) })
	}
}

func (m *rxManager) start(rx RXOptions) {
	// writer goroutine
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		for w := range m.writeQ {
			// bounds check for last block
			max := int64(m.fileSize) - w.off
			data := w.data
			if max < int64(len(data)) {
				data = data[:max]
			}
			_, _ = m.out.WriteAt(data, w.off)
			m.written.Add(uint64(len(data)))
			if m.met != nil {
				m.met.OnWrite(time.Now())
			}
			// debug: print when nearing completion
			if m.written.Load() >= m.fileSize {
				//nolint
				print("[rxbuf] wrote final bytes\n")
			}
		}
	}()
	// control writer goroutine (serialize writes; don't block actors)
	if m.ctrlW != nil {
		if m.ctrlOut == nil {
			// Large buffer to avoid dropping control under burst decode.
			// Dropping ACKs can leave the sender waiting in ARQ drain long after
			// the receiver has completed the transfer.
			m.ctrlOut = make(chan []byte, 65536)
		}
		m.ctrlWG.Add(1)
		go func() {
			defer m.ctrlWG.Done()
			defer m.ctrlDead.Store(true)
			type closeWriter interface{ Close() error }
			// If the underlying writer supports SetWriteDeadline, use it to avoid indefinite blocks.
			type deadlineWriter interface{ SetWriteDeadline(time.Time) error }
			cw, _ := m.ctrlW.(closeWriter)
			dw, _ := m.ctrlW.(deadlineWriter)
			defer func() {
				if cw != nil {
					_ = cw.Close()
				}
			}()
			for buf := range m.ctrlOut {
				// best-effort full write
				for off := 0; off < len(buf); {
					if dw != nil {
						_ = dw.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
					}
					n, err := m.ctrlW.Write(buf[off:])
					if err != nil {
						// drop on error; exit to avoid blocking shutdown
						return
					}
					if n <= 0 {
						return
					}
					off += n
				}
			}
		}()
	}

	// decode workers
	for i := 0; i < rx.Workers; i++ {
		m.wgDec.Add(1)
		go func() {
			defer m.wgDec.Done()
			for {
				select {
				case <-m.stopCh:
					return
				case b, ok := <-m.decodeQ:
					if !ok {
						return
					}
					if b == nil || b.done {
						continue
					}
					t0 := time.Now()
					b.decMu.Lock()
					ok, bytes, err := b.dec.Decode()
					b.decMu.Unlock()
					if err != nil || !ok {
						// Decoding failed; unqueue and wait for next DDL tick to decide NACK.
						m.mu.Lock()
						// Mark decode failure so the scheduler can request additional repairs
						// even if rx_unique>=K.
						rxu := b.srcSeenCount + len(b.syms)
						b.decodeFailed = true
						b.lastDecodeFailAt = time.Now()
						b.lastDecodeFailRxUnique = rxu
						b.queued = false
						m.mu.Unlock()
						continue
					}
					decNs := time.Since(t0).Nanoseconds()
					m.decTimeTotal.Add((decNs + 999_999) / 1_000_000) // keep existing ms counter for debug
					if m.met != nil {
						m.met.OnDecodeComputeNs(decNs)
					}
					// schedule a single contiguous write for this block
					span := m.blockSpan.Load()
					if span <= 0 {
						span = int64(b.K * b.L)
					}
					off := int64(b.id) * span
					m.writeQ <- writeTask{off: off, data: bytes}
					m.noteDelivered(off, len(bytes))
					m.decBlocks.Add(1)
					// release memory and mark done
					// capture stats before clearing; must hold m.mu because ingest mutates b.syms.
					var (
						rxUnique   int
						usedRep    int
						attemptIdx int
						firstSeen  time.Time
					)
					m.mu.Lock()
					if b.done {
						m.mu.Unlock()
						continue
					}
					firstSeen = b.firstSeen
					attemptIdx = b.attempt
					rxUnique = b.srcSeenCount + len(b.syms)
					// Used repairs is at least the number of received repair symbols.
					// (This may slightly overcount if repairs were redundant, but is stable and cheap.)
					repairRx := 0
					for e := range b.syms {
						if e >= b.K {
							repairRx++
						}
					}
					usedRep = repairRx
					for _, p := range b.syms {
						m.inUse.Add(int64(-len(p)))
					}
					b.syms = nil
					b.srcBuf = nil
					b.srcSeen = nil
					b.srcSeenCount = 0
					b.done = true
					delete(m.blocks, b.id)
					// remember completion to ignore late arrivals for this block
					m.completed[b.id] = struct{}{}
					m.mu.Unlock()
					// metrics: per-cluster decode event
					if m.met != nil {
						m.met.OnClusterDecoded(firstSeen, time.Now(), attemptIdx, usedRep)
					}
					// ACK success to sender if ctrl available
					if m.ctrlOut != nil {
						var buf bytespkg.Buffer
						_ = writeAck(&buf, AckSuccess{BlockID: uint32(b.id)})
						payload := buf.Bytes()
						dropped := false
						select {
						case m.ctrlOut <- payload:
							// ok
						default:
							if m.ctrlDead.Load() {
								dropped = true
								fmt.Fprintf(os.Stderr, "[arq] ctrl writer dead, dropping ACK block=%d\n", b.id)
							} else {
								t := time.NewTimer(200 * time.Millisecond)
								defer t.Stop()
								select {
								case m.ctrlOut <- payload:
									// queued
								case <-t.C:
									dropped = true
									fmt.Fprintf(os.Stderr, "[arq] ctrl queue enqueue timeout, dropping ACK block=%d\n", b.id)
								}
							}
						}
						if m.met != nil {
							m.met.OnCtrlTx(len(payload), "ack", dropped)
						}
						fmt.Fprintf(os.Stderr, "[arq] ack block=%d rx_unique=%d used_rep=%d attempt=%d\n", b.id, rxUnique, usedRep, attemptIdx)
					}
				}
			}
		}()
	}
	// DDL scheduler (soft deadline is configured via file header; see transfer.go).
	softDDL := m.softDDL
	m.wgDec.Add(1)
	go func() {
		defer m.wgDec.Done()
		// Faster scheduler tick for more responsive ARQ without large sleeps.
		t := time.NewTicker(1 * time.Millisecond)
		defer t.Stop()
		arqPoll := 8 * time.Millisecond
		if v := os.Getenv("QUIC_FEC_ARQ_POLL_MS"); v != "" {
			if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
				arqPoll = time.Duration(ms) * time.Millisecond
			}
		}
		minUnseenNack := 200 * time.Millisecond
		for {
			select {
			case <-m.stopCh:
				return
			case <-t.C:
			}
			now := time.Now()
			// collect work outside the lock
			type nackMsg struct {
				blockID uint32
				attempt int
				rxu     int
				send    bool
			}
			var toDecode []*rxBlock
			var nacks []nackMsg
			m.mu.Lock()
			for _, b := range m.blocks {
				if b.done || b.queued {
					continue
				}
				if now.After(b.nextDDL) || now.Equal(b.nextDDL) {
					nextDDL := now.Add(m.ddl)
					// Calculate the number of symbols still needed to reach K+1.
					if m.ctrlOut != nil {
						rxu := b.srcSeenCount + len(b.syms)
						deficit := b.K + 1 - rxu
						if deficit > 0 {
							// Seen-block soft deadline:
							// Count from lastSymAt (refreshed on every arrival). If idle for softDDL,
							// trigger NACK immediately.
							if !b.firstSeen.IsZero() {
								if !b.lastSymAt.IsZero() {
									due := b.lastSymAt.Add(softDDL)
									if now.Before(due) {
										// Not yet reached soft deadline; schedule exactly at due.
										nextDDL = due
										goto advanceDDL
									}
								} else {
									// If we somehow missed lastSymAt, fall back to firstSeen.
									due := b.firstSeen.Add(softDDL)
									if now.Before(due) {
										nextDDL = due
										goto advanceDDL
									}
								}
								// Soft deadline reached (or no timestamps): poll quickly after NACK scheduling.
								nextDDL = now.Add(minDur(m.ddl, arqPoll))
							}
							// Debounce: avoid spamming NACKs when nothing changes.
							// - For seen blocks: allow NACK after a short grace and then with backoff.
							// - For unseen placeholders: send at most once (or very rarely) only when
							//   the block ID is within the observed range.
							canNack := false
							if !b.firstSeen.IsZero() {
								// Seen block: NACK is governed by the soft deadline and a post-NACK wait.
								if b.nackBackoff <= 0 {
									b.nackBackoff = m.ddl
								}
								// If progress since last NACK, reset backoff.
								if rxu > b.lastNackRxUnique {
									b.nackBackoff = m.ddl
								}
								if (b.nackWaitUntil.IsZero() || !now.Before(b.nackWaitUntil)) &&
									(b.lastNackAt.IsZero() || now.Sub(b.lastNackAt) >= b.nackBackoff) {
									canNack = true
								}
							} else {
								// Unseen placeholder: only NACK if block is within [minSeen,maxSeen]
								// (i.e., we have evidence it should exist), and rate-limit heavily.
								// If totalBlocks is known, use [0,totalBlocks) so missing tail blocks are recoverable.
								inRange := false
								if m.totalBlocks > 0 {
									// With totalBlocks known (header parsed), we can safely NACK a small
									// prefix beyond what we've observed, so a fully-missing tail block can
									// still be recovered. Limit to (maxSeen+1) to avoid spamming NACKs for
									// the entire file.
									hi := m.maxSeen + 1
									if hi < 0 {
										hi = 0
									}
									if hi >= m.totalBlocks {
										hi = m.totalBlocks - 1
									}
									inRange = (hi >= 0 && int(b.id) >= 0 && int(b.id) <= hi)
								} else {
									inRange = (m.minSeen >= 0 && int(b.id) >= m.minSeen && int(b.id) <= m.maxSeen)
								}
								// For the immediate tail block (maxSeen+1), we still require a global idle
								// gap to avoid preemptive repairs during transient burst-loss gaps.
								isTail := int(b.id) == m.maxSeen+1
								needIdle := minUnseenNack
								if isTail {
									longer := 6 * m.ddl
									if longer > needIdle {
										needIdle = longer
									}
								}
								lastRx := m.lastRxAt.Load()
								idleOK := false
								if lastRx > 0 {
									idleOK = now.Sub(time.Unix(0, lastRx)) >= needIdle
								}
								// For interior gaps (b.id <= maxSeen), do NOT wait for global idle.
								// Otherwise a completely-erased block during a burst can only be NACKed
								// after traffic stops, which creates bimodal tail latency and low success
								// rates when R0 is small.
								gapOK := !isTail
								ageOK := false
								if !b.t0.IsZero() {
									ageOK = now.Sub(b.t0) >= minUnseenNack
								}
								if inRange && ((gapOK && ageOK) || (isTail && idleOK)) {
									if !b.unseenNackSent {
										canNack = true
									} else if !b.lastNackAt.IsZero() && now.Sub(b.lastNackAt) >= 4*m.ddl {
										// very slow retry
										canNack = true
									}
								}
							}
							if canNack {
								// Only count ARQ attempts when we actually send a NACK.
								b.attempt++
								// Clear decodeFailed when we decide to request more; this prevents
								// repeated decode-failure-driven NACKs from persisting after new symbols arrive.
								// It will be re-set by the decode worker if decode still fails.
								b.decodeFailed = false
								nacks = append(nacks, nackMsg{blockID: b.id, attempt: b.attempt, rxu: rxu, send: true})
								// Update per-block debounce state.
								if b.firstSeen.IsZero() {
									b.unseenNackSent = true
								}
								// Exponential backoff if no progress.
								if rxu <= b.lastNackRxUnique {
									if b.nackBackoff <= 0 {
										b.nackBackoff = m.ddl
									}
									b.nackBackoff = minDur(4*m.ddl, 2*b.nackBackoff)
								} else {
									b.nackBackoff = m.ddl
								}
								b.lastNackAt = now
								b.lastNackRxUnique = rxu
								// After sending a NACK, wait for repairs to arrive.
								// The wait is softDDL + 1.5*SRTT (using quic-go's smoothed RTT when available).
								srtt := latestServerSRTT()
								if srtt <= 0 {
									// Fallback to configured RTT when SRTT is not yet available.
									if rttStr := os.Getenv("RTT_MS"); rttStr != "" {
										if ms, err := strconv.Atoi(rttStr); err == nil && ms > 0 {
											srtt = time.Duration(ms) * time.Millisecond
										}
									}
								}
								wait := softDDL
								if srtt > 0 {
									wait += srtt + srtt/2
								}
								nextDDL = now.Add(wait)
								b.nackWaitUntil = nextDDL
							}
						}
					}
					// Only queue for decode when we have at least K uniques (decoder likely to succeed).
					// IMPORTANT: Do not mark b.queued unless we actually enqueue for decode; otherwise
					// blocks with syms<K would be stuck as 'queued' and stop receiving NACKs.
					if (b.srcSeenCount + len(b.syms)) >= b.K {
						b.queued = true
						toDecode = append(toDecode, b)
					}
				advanceDDL:
					// Always advance nextDDL so we retry after the interval.
					b.nextDDL = nextDDL
				}
			}
			m.mu.Unlock()
			// metrics: record DDL snapshot for each block scheduled
			if m.met != nil {
				for _, b := range toDecode {
					m.met.OnDDLTick(len(b.syms))
				}
			}
			// send control and schedule decodes without holding lock
			for _, n := range nacks {
				select {
				case <-m.stopCh:
					return
				default:
				}
				var buf bytespkg.Buffer
				_ = writeNack(&buf, NackNeedMore{
					BlockID:    n.blockID,
					AttemptIdx: uint16(n.attempt),
					RecvCount:  uint16(n.rxu),
				})
				payload := buf.Bytes()
				dropped := false
				select {
				case <-m.stopCh:
					return
				case m.ctrlOut <- payload:
					// ok
				default:
					if m.ctrlDead.Load() {
						dropped = true
						fmt.Fprintf(os.Stderr, "[arq] ctrl writer dead, dropping NACK block=%d\n", n.blockID)
					} else {
						t := time.NewTimer(200 * time.Millisecond)
						defer t.Stop()
						select {
						case <-m.stopCh:
							return
						case m.ctrlOut <- payload:
							// queued
						case <-t.C:
							dropped = true
							fmt.Fprintf(os.Stderr, "[arq] ctrl queue enqueue timeout, dropping NACK block=%d\n", n.blockID)
						}
					}
				}
				if m.met != nil {
					m.met.OnCtrlTx(len(payload), "nack", dropped)
				}
				fmt.Fprintf(os.Stderr, "[arq] nack block=%d recv_count=%d attempt=%d\n", n.blockID, n.rxu, n.attempt)
			}
			for _, b := range toDecode {
				// during shutdown, avoid blocking or panicking on closed decodeQ
				select {
				case <-m.stopCh:
					return
				default:
				}
				select {
				case m.decodeQ <- b:
				default:
					// If enqueue fails, do NOT leave the block stuck as queued.
					// Otherwise the scheduler will skip it (b.queued==true) and it will never
					// be retried for decode or NACKed again.
					m.mu.Lock()
					b.queued = false
					m.mu.Unlock()
				}
			}
		}
	}()
}

// ingest one symbol; returns whether accepted.
func (m *rxManager) ingest(blockID uint32, esi int, N, K, L int, data []byte, dataSize int) bool {
	// Record receive activity early (even if this symbol is later dropped as duplicate)
	// so the scheduler doesn't send unseen-block NACKs while traffic is ongoing.
	m.lastRxAt.Store(time.Now().UnixNano())
	isRepair := esi >= K
	if L <= 0 || len(data) > L {
		return false
	}
	// DATAGRAM mode gives us the actual payload length. Source symbols may be
	// shorter than L (most notably the final source symbol of the file); the
	// systematic fast path already stores them into a zero-initialized K*L
	// buffer. Repairs, however, are passed directly to the FEC decoder and
	// therefore must be explicitly padded to exactly L bytes.
	if isRepair && len(data) < L {
		padded := make([]byte, L)
		copy(padded, data)
		data = padded
	}
	m.mu.Lock()
	// On first observed symbol, record global K and compute total blocks.
	if m.K == 0 && K > 0 {
		m.K = K
		m.L = L
		m.blockSpan.Store(int64(K * L))
		if K > 0 && L > 0 {
			blk := uint64(K * L)
			m.totalBlocks = int((m.fileSize + blk - 1) / blk)
		}
		// Pre-create placeholders for all expected blocks to enable early ARQ on missing ones.
		if !m.seeded && m.totalBlocks > 0 && m.ctrlOut != nil {
			for i := 0; i < m.totalBlocks; i++ {
				bid := uint32(i)
				if _, ok := m.blocks[bid]; !ok {
					now := time.Now()
					m.blocks[bid] = &rxBlock{
						id:       bid,
						t0:       now,
						K:        m.K,
						N:        m.K,
						L:        m.L,
						dataSize: m.K * m.L,
						attempt:  0,
						nextDDL:  now.Add(m.ddl),
						syms:     make(map[int][]byte, m.K),
					}
				}
			}
			m.seeded = true
		}
	}
	// Drop any late symbols for blocks that were already completed.
	if _, ok := m.completed[blockID]; ok {
		m.mu.Unlock()
		return false
	}
	b := m.blocks[blockID]
	if b == nil {
		next := time.Now().Add(minDur(m.ddl, 20*time.Millisecond))
		b = &rxBlock{
			id:       blockID,
			t0:       time.Now(),
			K:        K,
			N:        N,
			L:        L,
			dataSize: dataSize,
			attempt:  0,
			nextDDL:  next,
			syms:     make(map[int][]byte, N),
		}
		m.blocks[blockID] = b
	} else {
		// If this was a pre-seeded placeholder, update it with real block parameters
		// on the first actual symbol. This matters when the last block uses a smaller K.
		if b.srcSeenCount == 0 && len(b.syms) == 0 {
			if K > 0 {
				b.K = K
			}
			if N > 0 {
				b.N = N
			}
			if L > 0 {
				b.L = L
			}
			if dataSize > 0 {
				b.dataSize = dataSize
			}
		}
	}
	// Note: we intentionally update per-block activity timestamps only after we
	// know this symbol is innovative (non-duplicate) and admitted into state.
	// Otherwise, repeated duplicate retransmissions could indefinitely postpone
	// the soft-deadline and suppress NACK retries for a still-deficit block.
	// If this is the first time we observe any block (minSeen==-1), backfill placeholders for [0..blockID-1].
	// Note: block numbering always starts from 0. If the first observed block has blockID>0 (i.e., block 0
	// was fully erased), we must still consider block 0 in-range for unseen-block ARQ; otherwise the receiver
	// would never NACK it and the transfer can complete with exactly one block missing.
	if m.minSeen == -1 {
		m.minSeen = 0
		m.maxSeen = int(blockID)
		if blockID > 0 && m.ctrlOut != nil && m.K > 0 && m.L > 0 {
			for i := 0; i < int(blockID); i++ {
				bid := uint32(i)
				if _, ok := m.blocks[bid]; !ok {
					now := time.Now()
					m.blocks[bid] = &rxBlock{
						id:       bid,
						t0:       now,
						K:        m.K,
						N:        m.K, // unknown yet; doesn't matter for NACK
						L:        m.L,
						dataSize: m.K * m.L,
						attempt:  0,
						nextDDL:  now.Add(m.ddl),
						syms:     make(map[int][]byte, m.K),
					}
				}
			}
		}
	} else {
		// Update seen range and create placeholders for forward gaps
		if int(blockID) > m.maxSeen {
			prev := m.maxSeen
			m.maxSeen = int(blockID)
			if prev >= 0 && m.ctrlOut != nil && m.K > 0 && m.L > 0 {
				for i := prev + 1; i < int(blockID); i++ {
					bid := uint32(i)
					if _, ok := m.blocks[bid]; !ok {
						now := time.Now()
						m.blocks[bid] = &rxBlock{
							id:       bid,
							t0:       now,
							K:        m.K,
							N:        m.K,
							L:        m.L,
							dataSize: m.K * m.L,
							attempt:  0,
							nextDDL:  now.Add(m.ddl),
							syms:     make(map[int][]byte, m.K),
						}
					}
				}
			}
		}
		if m.minSeen == -1 || int(blockID) < m.minSeen {
			m.minSeen = int(blockID)
		}
	}
	// drop duplicates (systematic vs repair symbols)
	if !isRepair {
		if b.srcSeen != nil && esi >= 0 && esi < len(b.srcSeen) && b.srcSeen[esi] {
			m.mu.Unlock()
			return false
		}
	} else {
		if _, ok := b.syms[esi]; ok {
			m.mu.Unlock()
			return false
		}
	}
	// prevent pathological growth: cap stored repairs per block (e.g., 8*K) for small-K scenarios
	if isRepair && len(b.syms) > 0 {
		// count repairs-only
		repOnly := 0
		for e := range b.syms {
			if e >= K {
				repOnly++
			}
		}
		if repOnly >= 8*K {
			m.mu.Unlock()
			m.dropsRepairs.Add(1)
			return false
		}
	}
	// Memory admission decision (post-dup check, with block context):
	cur := m.inUse.Load()
	admit := true
	if isRepair {
		// Repairs: allow if within budget, or up to 2x budget; always allow bootstrap
		// for blocks with very few symbols so empty blocks can progress.
		if int(cur)+len(data) > m.budget {
			// Bootstrap priority: if this block has < 2 uniques, admit regardless.
			if len(b.syms) < 2 {
				admit = true
			} else if int(cur)+len(data) <= 2*m.budget {
				admit = true
			} else {
				admit = false
			}
		}
	} else {
		// Data symbols: always admit; these directly improve decode probability.
		admit = true
	}
	if !admit {
		m.mu.Unlock()
		m.dropsRepairs.Add(1)
		return false
	}
	// Track innovative per-block receive activity.
	nowSym := time.Now()
	b.lastSymAt = nowSym
	// Any innovative symbol arrival may resolve rank deficiency.
	b.decodeFailed = false
	// If we previously scheduled a long post-NACK wait, receiving any *innovative*
	// symbol should restart the soft-deadline countdown as soon as possible.
	if m.softDDL > 0 && !b.done && !b.queued {
		due := nowSym.Add(m.softDDL)
		if !b.nackWaitUntil.IsZero() && due.Before(b.nackWaitUntil) {
			due = b.nackWaitUntil
		}
		if b.nextDDL.After(due) {
			b.nextDDL = due
		}
	}
	// Update block meta from header for placeholders or unknowns.
	if b.K != K || b.L != L || b.dataSize != dataSize {
		b.K = K
		b.L = L
		b.dataSize = dataSize
		// Reset systematic fast-path state if parameters changed.
		b.srcBuf = nil
		b.srcSeen = nil
		b.srcSeenCount = 0
	}

	// Store symbol.
	// Repairs are kept in a map and accounted against the memory budget.
	// Systematic (source) symbols are written directly into a preallocated block buffer.
	symLen := len(data)
	var p []byte
	if isRepair {
		p = make([]byte, len(data))
		copy(p, data)
		b.syms[esi] = p
		m.inUse.Add(int64(len(p)))
	} else {
		if b.srcBuf == nil {
			// Allocate K*L to keep L-sized slices stable for decoder input, even if the
			// last block is partial (dataSize < K*L).
			b.srcBuf = make([]byte, K*L)
		}
		if b.srcSeen == nil || len(b.srcSeen) != K {
			b.srcSeen = make([]bool, K)
			b.srcSeenCount = 0
		}
		start := esi * L
		if start < len(b.srcBuf) {
			end := start + len(data)
			if end > len(b.srcBuf) {
				end = len(b.srcBuf)
			}
			copy(b.srcBuf[start:end], data[:end-start])
		}
		b.srcSeen[esi] = true
		b.srcSeenCount++
		// Feed decoder from stable memory.
		if start >= 0 && start+L <= len(b.srcBuf) {
			p = b.srcBuf[start : start+L]
		} else {
			p = data
		}
	}
	// Lazily create decoder when needed.
	// The decode worker assumes b.dec is non-nil once a block is queued.
	if b.dec == nil {
		dec, err := fec.NewRaptorQDecoder(b.dataSize, b.L)
		if err == nil {
			b.dec = dec
		}
	}
	// metrics: mark first unique for this block and file + arrival counts
	if b.firstSeen.IsZero() {
		b.firstSeen = time.Now()
		if m.t0First.IsZero() {
			m.t0First = b.firstSeen
		}
	}
	if m.met != nil {
		now := time.Now()
		m.met.OnUniqueSymbol(symLen, now, esi >= K)
		if !m.met.gotFirst {
			m.met.OnFirstUniqueSymbol(now)
		}
	}

	// Fast path for systematic delivery: if we received all source symbols (0..K-1),
	// the block is already assembled in srcBuf.
	var sysBuf []byte
	var sysOff int64
	var sysRxUnique int
	var sysUsedRep int
	var sysAttempt int
	var sysFirstSeen time.Time
	var sysBlockID uint32
	if !b.done && b.srcBuf != nil && b.srcSeenCount >= K && K > 0 {
		if b.dataSize > 0 && b.dataSize <= len(b.srcBuf) {
			sysBuf = b.srcBuf[:b.dataSize]
		} else {
			sysBuf = b.srcBuf
		}
		span := m.blockSpan.Load()
		if span <= 0 {
			span = int64(b.K * b.L)
		}
		sysOff = int64(b.id) * span
		sysRxUnique = b.srcSeenCount + len(b.syms)
		sysUsedRep = max(0, sysRxUnique-b.K)
		sysAttempt = b.attempt
		sysFirstSeen = b.firstSeen
		sysBlockID = b.id
		// Release any stored repairs (rare on loss=0), and mark done under lock.
		for _, pp := range b.syms {
			m.inUse.Add(int64(-len(pp)))
		}
		b.syms = nil
		b.srcBuf = nil
		b.srcSeen = nil
		b.srcSeenCount = 0
		b.done = true
		delete(m.blocks, b.id)
		m.completed[b.id] = struct{}{}
	}
	m.mu.Unlock()

	if sysBuf != nil {
		m.writeQ <- writeTask{off: sysOff, data: sysBuf}
		m.noteDelivered(sysOff, len(sysBuf))
		m.decBlocks.Add(1)
		if m.met != nil {
			m.met.OnClusterDecoded(sysFirstSeen, time.Now(), sysAttempt, sysUsedRep)
		}
		if m.ctrlOut != nil {
			var buf bytespkg.Buffer
			_ = writeAck(&buf, AckSuccess{BlockID: uint32(sysBlockID)})
			payload := buf.Bytes()
			dropped := false
			select {
			case m.ctrlOut <- payload:
				// ok
			default:
				if m.ctrlDead.Load() {
					dropped = true
					fmt.Fprintf(os.Stderr, "[arq] ctrl writer dead, dropping ACK block=%d\n", sysBlockID)
				} else {
					t := time.NewTimer(200 * time.Millisecond)
					defer t.Stop()
					select {
					case m.ctrlOut <- payload:
						// queued
					case <-t.C:
						dropped = true
						fmt.Fprintf(os.Stderr, "[arq] ctrl queue enqueue timeout, dropping ACK block=%d\n", sysBlockID)
					}
				}
			}
			if m.met != nil {
				m.met.OnCtrlTx(len(payload), "ack", dropped)
			}
			fmt.Fprintf(os.Stderr, "[arq] ack block=%d rx_unique=%d used_rep=%d attempt=%d\n", sysBlockID, sysRxUnique, sysUsedRep, sysAttempt)
		}
		return true
	}

	// feed decoder; if decoder reports readiness, queue a decode
	if b.dec == nil {
		// Shouldn't happen (we create it lazily above), but avoid panics.
		return true
	}
	b.decMu.Lock()
	ready, _ := b.dec.AddSymbol(uint32(esi), p)
	b.decMu.Unlock()
	if ready {
		// mark queued under lock, send outside
		send := false
		m.mu.Lock()
		if !b.queued && !b.done {
			b.queued = true
			send = true
		}
		m.mu.Unlock()
		if send {
			// avoid blocking/panic if shutting down
			select {
			case <-m.stopCh:
				// skip
			default:
				select {
				case m.decodeQ <- b:
				default:
					// If enqueue fails, clear queued so the scheduler can retry / NACK.
					m.mu.Lock()
					b.queued = false
					m.mu.Unlock()
				}
			}
		}
	}
	return true
}

func (m *rxManager) closeAndFinalize() (string, error) {
	// stop scheduling, finish decoders, then drain writer
	close(m.stopCh)
	// wait for all decoders and scheduler to finish (they observe stopCh)
	m.wgDec.Wait()
	// stop ctrl writer after decoders (no more control messages)
	if m.ctrlOut != nil {
		close(m.ctrlOut)
		m.ctrlWG.Wait()
	}
	// now it's safe to close writeQ; writer will exit after draining
	close(m.writeQ)
	m.wg.Wait()
	// Best-effort flush; no extra fsync here
	if err := m.out.Close(); err != nil {
		return "", err
	}
	finalPath := filepath.Join(m.outDir, filepath.Base(m.tmpPath[:len(m.tmpPath)-5]))
	if err := os.Rename(m.tmpPath, finalPath); err != nil {
		return "", err
	}
	return finalPath, nil
}

// helpers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
