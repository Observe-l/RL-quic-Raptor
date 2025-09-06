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
	// metrics timestamps
	firstSeen time.Time
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
					m.decTimeTotal.Add(time.Since(t0).Milliseconds())
					// schedule a single contiguous write for this block
					off := int64(int(b.id) * b.K * b.L)
					m.writeQ <- writeTask{off: off, data: bytes}
					m.decBlocks.Add(1)
					// release memory and mark done
					// capture stats before clearing
					rxUnique := len(b.syms)
					usedRep := max(0, rxUnique-b.K)
					m.mu.Lock()
					for _, p := range b.syms {
						m.inUse.Add(int64(-len(p)))
					}
					b.syms = nil
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
						// non-blocking enqueue; drop if full (next events will resend state)
						select {
						case m.ctrlOut <- buf.Bytes():
						default:
							fmt.Fprintf(os.Stderr, "[arq] ctrl queue full, dropping ACK block=%d\n", b.id)
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
					b.queued = true
					b.nextDDL = now.Add(m.ddl)
					// calculate NACK recommendation under lock
					if m.ctrlOut != nil {
						deficit := b.K - len(b.syms)
						if deficit > 0 {
							// Only count ARQ attempts when we actually need more symbols
							b.attempt++
							// Be more aggressive: ask for at least the deficit (min 4)
							rec := deficit
							if rec < 4 {
								rec = 4
							}
							nacks = append(nacks, nackMsg{blockID: b.id, attempt: b.attempt, rxu: len(b.syms), rec: rec, send: true})
						}
					}
					toDecode = append(toDecode, b)
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
				// non-blocking send; if closed or full, skip
				select {
				case <-m.stopCh:
					return
				case m.ctrlOut <- buf.Bytes():
				default:
					// best-effort: drop if queue full
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
	// admission: drop repairs if over budget
	cur := m.inUse.Load()
	if int(cur)+len(data) > m.budget && isRepair {
		m.dropsRepairs.Add(1)
		return false
	}
	m.mu.Lock()
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
		dec, err := fec.NewRaptorQDecoder(dataSize, L)
		if err != nil {
			m.mu.Unlock()
			return false
		}
		b.dec = dec
		m.blocks[blockID] = b
	}
	// drop duplicates
	if _, ok := b.syms[esi]; ok {
		m.mu.Unlock()
		return false
	}
	// prevent pathological growth: cap stored repairs per block to 4*K
	if isRepair && len(b.syms) > 0 {
		// count repairs-only
		repOnly := 0
		for e := range b.syms {
			if e >= K {
				repOnly++
			}
		}
		if repOnly >= 4*K {
			m.mu.Unlock()
			m.dropsRepairs.Add(1)
			return false
		}
	}
	// store symbol
	p := make([]byte, len(data))
	copy(p, data)
	b.syms[esi] = p
	m.inUse.Add(int64(len(p)))
	// metrics: mark first unique for this block and file + arrival counts
	if b.firstSeen.IsZero() {
		b.firstSeen = time.Now()
	}
	if m.met != nil {
		now := time.Now()
		m.met.OnUniqueSymbol(len(p), now, esi >= K)
		if !m.met.gotFirst {
			m.met.OnFirstUniqueSymbol(now)
		}
	}
	m.mu.Unlock()

	// feed decoder; if decoder reports readiness, queue a decode
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
