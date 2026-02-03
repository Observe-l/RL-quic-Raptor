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

// RXOptions configures the receiver buffer.
type RXOptions struct {
	BudgetBytes int // total bytes for buffered symbols (default 10MB)
	Workers     int // decode workers (default numCPU)
}

func (o *RXOptions) setDefaults() {
	if o.BudgetBytes <= 0 {
		o.BudgetBytes = 64 * 1024 * 1024
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

	dec    *fec.RaptorQDecoder
	decMu  sync.Mutex // guards decoder AddSymbol/Decode; decoder is not goroutine-safe
	queued bool
	done   bool
	// store received symbols by ESI to avoid duplicates and allow release
	syms map[int][]byte
	// Fast path for systematic source symbols (ESI < K): write directly into a block buffer
	// to avoid per-symbol allocations and map overhead on low/no-loss links.
	srcBuf       []byte
	srcSeen      []bool
	srcSeenCount int
	// metrics timestamps
	firstSeen time.Time
}

// rxManager owns memory accounting, blocks, decode and write queues.
type rxManager struct {
	// config
	budget int

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
	wgDec sync.WaitGroup // decoders

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
	// first arrival timestamp (for metrics / debug)
	t0First time.Time
}

func newRXManager(fileSize uint64, K, L int, outDir, baseName string, rx RXOptions) (*rxManager, error) {
	rx.setDefaults()
	m := &rxManager{
		budget:    rx.BudgetBytes,
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
	}
	if K > 0 && L > 0 {
		blk := uint64(K * L)
		m.totalBlocks = int((fileSize + blk - 1) / blk)
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
			// Large buffer to avoid dropping control under burst decode.
			// Dropping ACKs can leave the sender waiting in ARQ drain long after
			// the receiver has completed the transfer.
			m.ctrlOut = make(chan []byte, 65536)
		}
		m.ctrlWG.Add(1)
		go func() {
			defer m.ctrlWG.Done()
			defer m.ctrlDead.Store(true)
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
						// Decoding failed; wait for more symbols.
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
						m.met.OnClusterDecoded(b.firstSeen, time.Now(), 0, usedRep)
					}
					// ACK success to sender if ctrl available
					if m.ctrlOut != nil {
						var buf bytespkg.Buffer
						_ = writeAck(&buf, AckSuccess{
							FileID:          0,
							ClusterID:       uint32(b.id),
							AttemptIdx:      0,
							RxUnique:        uint16(rxUnique),
							UsedRepairs:     uint16(usedRep),
							DecodeLatencyMs: uint32(time.Since(t0).Milliseconds()),
						})
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
						fmt.Fprintf(os.Stderr, "[arq] ack block=%d rx_unique=%d used_rep=%d\n", b.id, rxUnique, usedRep)
					}
				}
			}
		}()
	}
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
			syms:     make(map[int][]byte, N),
		}
		m.blocks[blockID] = b
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
	// metrics: mark first/last unique for this block and file + arrival counts
	nowTs := time.Now()
	if b.firstSeen.IsZero() {
		b.firstSeen = nowTs
		if m.t0First.IsZero() {
			m.t0First = b.firstSeen
		}
	}
	// Receiver doesn't run application-layer ARQ; sender schedules repairs based on QUIC loss signals.
	if m.met != nil {
		m.met.OnUniqueSymbol(symLen, nowTs, esi >= K)
		if !m.met.gotFirst {
			m.met.OnFirstUniqueSymbol(nowTs)
		}
	}

	// Fast path for systematic delivery: if we received all source symbols (0..K-1),
	// the block is already assembled in srcBuf.
	var sysBuf []byte
	var sysOff int64
	var sysRxUnique int
	var sysUsedRep int
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
			m.met.OnClusterDecoded(sysFirstSeen, time.Now(), 0, sysUsedRep)
		}
		if m.ctrlOut != nil {
			var buf bytespkg.Buffer
			_ = writeAck(&buf, AckSuccess{
				FileID:          0,
				ClusterID:       uint32(sysBlockID),
				AttemptIdx:      0,
				RxUnique:        uint16(sysRxUnique),
				UsedRepairs:     uint16(sysUsedRep),
				DecodeLatencyMs: 0,
			})
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
			fmt.Fprintf(os.Stderr, "[arq] ack block=%d rx_unique=%d used_rep=%d\n", sysBlockID, sysRxUnique, sysUsedRep)
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
					// drop if full; subsequent ingests / PROG will retry
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
	finalPath := filepath.Join(m.outDir, filepath.Base(m.tmpPath[:len(m.tmpPath)-5]))
	// Match raw QUIC behavior: do not reread the output file unless the sender
	// explicitly provided a non-zero SHA256 to verify.
	var zero [32]byte
	if expectedSHA == zero {
		if err := os.Rename(m.tmpPath, finalPath); err != nil {
			return "", err
		}
		return finalPath, nil
	}
	// Verify SHA by reopening file
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
					rxu := b.srcSeenCount + len(b.syms)
					fmt.Fprintf(os.Stderr, "[rx-finalize] block=%d rx_unique=%d K=%d\n", b.id, rxu, b.K)
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
