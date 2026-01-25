package fecquic

import (
	bytespkg "bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/fec"
)

// RXOptions configures the receiver buffer and scheduler.
type RXOptions struct {
	BudgetBytes int           // total bytes for buffered symbols (default 10MB)
	DDL         time.Duration // fixed decode deadline per block (default 50ms)
	Workers     int           // decode workers (default numCPU)
}

func (o *RXOptions) setDefaults() {
	if o.BudgetBytes <= 0 {
		o.BudgetBytes = 64 * 1024 * 1024
	}
	if o.DDL <= 0 {
		o.DDL = 50 * time.Millisecond
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
	id       uint16
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
	// ARQ de-bounce state
	lastNackAt       time.Time
	lastNackRxUnique int
	nackBackoff      time.Duration
	unseenNackSent   bool
}

// rxManager owns memory accounting, blocks, decode and write queues.
type rxManager struct {
	// config
	budget int
	ddl    time.Duration

	// file params
	fileSize uint64
	K, L     int
	outDir   string
	baseName string
	// totalBlocks is computed once K is known: ceil(fileSize / (K*L))
	totalBlocks int

	// state
	mu     sync.Mutex
	inUse  atomic.Int64
	blocks map[uint16]*rxBlock
	// completed remembers blocks that have already been fully decoded and written,
	// so late-arriving symbols for those blocks are ignored instead of recreating state.
	completed map[uint16]struct{}

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
	ctrlW   io.Writer   // underlying stream
	ctrlOut chan []byte // buffered queue to dedicated writer
	ctrlWG  sync.WaitGroup
	// server metrics aggregator
	met *serverMetrics
	// first arrival timestamp (for missing-block ARQ heuristics)
	t0First time.Time

	// tracking for missing blocks to NACK
	minSeen int  // first seen block id
	maxSeen int  // max seen block id
	seeded  bool // placeholders pre-created for all blocks when K known
}

func newRXManager(fileSize uint64, K, L int, outDir, baseName string, rx RXOptions) (*rxManager, error) {
	rx.setDefaults()
	m := &rxManager{
		budget:    rx.BudgetBytes,
		ddl:       rx.DDL,
		fileSize:  fileSize,
		K:         K,
		L:         L,
		outDir:    outDir,
		baseName:  baseName,
		blocks:    make(map[uint16]*rxBlock),
		completed: make(map[uint16]struct{}),
		decodeQ:   make(chan *rxBlock, 1024),
		writeQ:    make(chan writeTask, 8192),
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
		minSeen:   -1,
		maxSeen:   -1,
	}
	finalBase := baseName
	if finalBase == "" {
		finalBase = "qfec_recv.bin"
	}
	finalBase += ".recv"
	m.tmpPath = filepath.Join(outDir, finalBase+".part")
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
			m.ctrlOut = make(chan []byte, 2048)
		}
		m.ctrlWG.Add(1)
		go func() {
			defer m.ctrlWG.Done()
			// If the underlying writer supports SetWriteDeadline, use it to avoid indefinite blocks.
			type deadlineWriter interface{ SetWriteDeadline(time.Time) error }
			dw, _ := m.ctrlW.(deadlineWriter)
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
					off := int64(int(b.id) * b.K * b.L)
					m.writeQ <- writeTask{off: off, data: bytes}
					m.noteDelivered(off, len(bytes))
					m.decBlocks.Add(1)
					// release memory and mark done
					// capture stats before clearing
					rxUnique := b.srcSeenCount + len(b.syms)
					// Used repairs is at least the number of received repair symbols.
					// (This may slightly overcount if repairs were redundant, but is stable and cheap.)
					repairRx := 0
					for e := range b.syms {
						if e >= b.K {
							repairRx++
						}
					}
					usedRep := repairRx
					m.mu.Lock()
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
						m.met.OnClusterDecoded(b.firstSeen, time.Now(), b.attempt, usedRep)
					}
					// ACK success to sender if ctrl available
					if m.ctrlOut != nil {
						var buf bytespkg.Buffer
						_ = writeAck(&buf, AckSuccess{
							FileID:          0,
							ClusterID:       uint32(b.id),
							AttemptIdx:      uint16(b.attempt),
							RxUnique:        uint16(rxUnique),
							UsedRepairs:     uint16(usedRep),
							DecodeLatencyMs: uint32(time.Since(t0).Milliseconds()),
						})
						payload := buf.Bytes()
						// non-blocking enqueue; drop if full (next events will resend state)
						dropped := false
						select {
						case m.ctrlOut <- payload:
							// ok
						default:
							dropped = true
							fmt.Fprintf(os.Stderr, "[arq] ctrl queue full, dropping ACK block=%d\n", b.id)
						}
						if m.met != nil {
							m.met.OnCtrlTx(len(payload), "ack", dropped)
						}
						fmt.Fprintf(os.Stderr, "[arq] ack block=%d rx_unique=%d used_rep=%d attempt=%d\n", b.id, rxUnique, usedRep, b.attempt)
					}
				}
			}
		}()
	}
	// DDL scheduler
	m.wgDec.Add(1)
	go func() {
		defer m.wgDec.Done()
		// Faster scheduler tick for more responsive ARQ without large sleeps.
		t := time.NewTicker(1 * time.Millisecond)
		defer t.Stop()
		minSeenNack := 20 * time.Millisecond
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
				blockID uint16
				attempt int
				rxu     int
				rec     int
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
					// Calculate NACK recommendation under lock for deficit cases.
					if m.ctrlOut != nil {
						rxu := len(b.syms)
						deficit := b.K - rxu
						if deficit > 0 {
							// Debounce: avoid spamming NACKs when nothing changes.
							// - For seen blocks: allow NACK after a short grace and then with backoff.
							// - For unseen placeholders: send at most once (or very rarely) only when
							//   the block ID is within the observed range.
							canNack := false
							if !b.firstSeen.IsZero() {
								// Seen block: require a minimum time since first symbol.
								if now.Sub(b.firstSeen) >= minSeenNack {
									if b.nackBackoff <= 0 {
										b.nackBackoff = m.ddl
									}
									// If progress since last NACK, reset backoff.
									if rxu > b.lastNackRxUnique {
										b.nackBackoff = m.ddl
									}
									if b.lastNackAt.IsZero() || now.Sub(b.lastNackAt) >= b.nackBackoff {
										canNack = true
									}
								}
							} else {
								// Unseen placeholder: only NACK if block is within [minSeen,maxSeen]
								// (i.e., we have evidence it should exist), and rate-limit heavily.
								// If totalBlocks is known, use [0,totalBlocks) so missing tail blocks are recoverable.
								inRange := false
								if m.totalBlocks > 0 {
									inRange = int(b.id) >= 0 && int(b.id) < m.totalBlocks
								} else {
									inRange = (m.minSeen >= 0 && int(b.id) >= m.minSeen && int(b.id) <= m.maxSeen)
								}
								if inRange && !m.t0First.IsZero() && now.Sub(m.t0First) >= minUnseenNack {
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
								// Recommend at least the deficit (min 4)
								rec := deficit
								if rec < 4 {
									rec = 4
								}
								nacks = append(nacks, nackMsg{blockID: b.id, attempt: b.attempt, rxu: rxu, rec: rec, send: true})
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
							}
						}
					}
					// Only queue for decode when we have at least K uniques (decoder likely to succeed).
					// IMPORTANT: Do not mark b.queued unless we actually enqueue for decode; otherwise
					// blocks with syms<K would be stuck as 'queued' and stop receiving NACKs.
					if len(b.syms) >= b.K {
						b.queued = true
						toDecode = append(toDecode, b)
					}
					// Always advance nextDDL so we retry after the interval.
					b.nextDDL = now.Add(m.ddl)
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
					FileID:         0,
					ClusterID:      uint32(n.blockID),
					AttemptIdx:     uint16(n.attempt),
					RxUnique:       uint16(n.rxu),
					RecommendExtra: uint16(n.rec),
					Reason:         0,
				})
				payload := buf.Bytes()
				// non-blocking send; if closed or full, skip
				dropped := false
				select {
				case <-m.stopCh:
					return
				case m.ctrlOut <- payload:
				default:
					// best-effort: drop if queue full
					dropped = true
				}
				if m.met != nil {
					m.met.OnCtrlTx(len(payload), "nack", dropped)
				}
				fmt.Fprintf(os.Stderr, "[arq] nack block=%d rx_unique=%d rec_extra=%d attempt=%d\n", n.blockID, n.rxu, n.rec, n.attempt)
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
					// drop if queue is full; next tick will retry
				}
			}
		}
	}()
}

// ingest one symbol; returns whether accepted.
func (m *rxManager) ingest(blockID uint16, esi int, N, K, L int, data []byte, dataSize int) bool {
	isRepair := esi >= K
	m.mu.Lock()
	// On first observed symbol, record global K and compute total blocks.
	if m.K == 0 && K > 0 {
		m.K = K
		m.L = L
		if K > 0 && L > 0 {
			blk := uint64(K * L)
			m.totalBlocks = int((m.fileSize + blk - 1) / blk)
		}
		// Pre-create placeholders for all expected blocks to enable early ARQ on missing ones.
		if !m.seeded && m.totalBlocks > 0 && m.ctrlOut != nil {
			for i := 0; i < m.totalBlocks; i++ {
				bid := uint16(i)
				if _, ok := m.blocks[bid]; !ok {
					m.blocks[bid] = &rxBlock{
						id:       bid,
						K:        m.K,
						N:        m.K,
						L:        m.L,
						dataSize: m.K * m.L,
						attempt:  0,
						nextDDL:  time.Now().Add(m.ddl),
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
		b = &rxBlock{
			id:       blockID,
			t0:       time.Now(),
			K:        K,
			N:        N,
			L:        L,
			dataSize: dataSize,
			attempt:  0,
			nextDDL:  time.Now().Add(m.ddl),
			syms:     make(map[int][]byte, N),
		}
		m.blocks[blockID] = b
	}
	// If this is the first time we observe any block (minSeen==-1), backfill placeholders for [0..blockID-1].
	if m.minSeen == -1 {
		m.minSeen = int(blockID)
		m.maxSeen = int(blockID)
		if blockID > 0 && m.ctrlOut != nil && m.K > 0 && m.L > 0 {
			for i := 0; i < int(blockID); i++ {
				bid := uint16(i)
				if _, ok := m.blocks[bid]; !ok {
					m.blocks[bid] = &rxBlock{
						id:       bid,
						K:        m.K,
						N:        m.K, // unknown yet; doesn't matter for NACK
						L:        m.L,
						dataSize: m.K * m.L,
						attempt:  0,
						nextDDL:  time.Now().Add(m.ddl),
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
					bid := uint16(i)
					if _, ok := m.blocks[bid]; !ok {
						m.blocks[bid] = &rxBlock{
							id:       bid,
							K:        m.K,
							N:        m.K,
							L:        m.L,
							dataSize: m.K * m.L,
							attempt:  0,
							nextDDL:  time.Now().Add(m.ddl),
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
	var sysBlockID uint16
	if !b.done && b.srcBuf != nil && b.srcSeenCount >= K && K > 0 {
		if b.dataSize > 0 && b.dataSize <= len(b.srcBuf) {
			sysBuf = b.srcBuf[:b.dataSize]
		} else {
			sysBuf = b.srcBuf
		}
		sysOff = int64(int(b.id) * b.K * b.L)
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
			_ = writeAck(&buf, AckSuccess{
				FileID:          0,
				ClusterID:       uint32(sysBlockID),
				AttemptIdx:      uint16(sysAttempt),
				RxUnique:        uint16(sysRxUnique),
				UsedRepairs:     uint16(sysUsedRep),
				DecodeLatencyMs: 0,
			})
			payload := buf.Bytes()
			dropped := false
			select {
			case m.ctrlOut <- payload:
			default:
				dropped = true
				fmt.Fprintf(os.Stderr, "[arq] ctrl queue full, dropping ACK block=%d\n", sysBlockID)
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
					// drop if full; next DDL tick will schedule
				}
			}
		}
	}
	return true
}

func (m *rxManager) closeAndFinalize(expectedSHA [32]byte) (string, error) {
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
	// Verify SHA by reopening file
	finalPath := filepath.Join(m.outDir, filepath.Base(m.tmpPath[:len(m.tmpPath)-5]))
	out, err := os.Open(m.tmpPath)
	if err != nil {
		return "", err
	}
	sum, _, err := ComputeSHA256(out)
	_ = out.Close()
	if err != nil {
		return "", err
	}
	if sum != expectedSHA {
		// Diagnostics: report number of pending (unfinished) blocks and their rx_unique
		func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			pending := len(m.blocks)
			if pending > 0 {
				fmt.Fprintf(os.Stderr, "[rx-finalize] pending_blocks=%d\n", pending)
				i := 0
				for _, b := range m.blocks {
					fmt.Fprintf(os.Stderr, "[rx-finalize] block=%d rx_unique=%d K=%d attempts=%d\n", b.id, len(b.syms), b.K, b.attempt)
					i++
					if i >= 8 {
						break
					}
				}
			}
			// Also, if we know totalBlocks, list a few missing block IDs with zero symbols.
			if m.totalBlocks > 0 {
				missing := 0
				for i := 0; i < m.totalBlocks && missing < 8; i++ {
					bid := uint16(i)
					if _, ok := m.blocks[bid]; !ok {
						if _, done := m.completed[bid]; !done {
							fmt.Fprintf(os.Stderr, "[rx-finalize] missing_block=%d rx_unique=0\n", bid)
							missing++
						}
					}
				}
			}
		}()
		return "", errors.New("sha256 mismatch")
	}
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
