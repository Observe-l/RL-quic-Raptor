package fecquic

import (
	"errors"
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
		o.BudgetBytes = 10 * 1024 * 1024
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

	dec    *fec.RaptorQDecoder
	haveU  int
	queued bool
	done   bool
	// store received symbols by ESI to avoid duplicates and allow release
	syms map[int][]byte
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

	// queues
	decodeQ chan *rxBlock
	writeQ  chan writeTask
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// writer
	out     *os.File
	outPath string
	tmpPath string
	written atomic.Uint64

	// metrics
	decBlocks    atomic.Int64
	decTimeTotal atomic.Int64 // ms
	dropsRepairs atomic.Int64
}

func newRXManager(fileSize uint64, K, L int, outDir, baseName string, rx RXOptions) (*rxManager, error) {
	rx.setDefaults()
	m := &rxManager{
		budget:   rx.BudgetBytes,
		ddl:      rx.DDL,
		fileSize: fileSize,
		K:        K,
		L:        L,
		outDir:   outDir,
		baseName: baseName,
		blocks:   make(map[uint16]*rxBlock),
		decodeQ:  make(chan *rxBlock, 1024),
		writeQ:   make(chan writeTask, 8192),
		stopCh:   make(chan struct{}),
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
		}
	}()
	// decode workers
	for i := 0; i < rx.Workers; i++ {
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			for b := range m.decodeQ {
				if b.done {
					continue
				}
				if b.haveU < b.K {
					// not ready yet
					b.queued = false
					continue
				}
				t0 := time.Now()
				ok, bytes, err := b.dec.Decode()
				if err != nil || !ok {
					// decoding failed; likely need more symbols
					b.queued = false
					continue
				}
				m.decTimeTotal.Add(time.Since(t0).Milliseconds())
				// schedule a single contiguous write for this block
				off := int64(int(b.id) * b.K * b.L)
				m.writeQ <- writeTask{off: off, data: bytes}
				m.decBlocks.Add(1)
				// release memory and mark done
				m.mu.Lock()
				for _, p := range b.syms {
					m.inUse.Add(int64(-len(p)))
				}
				b.syms = nil
				b.done = true
				delete(m.blocks, b.id)
				m.mu.Unlock()
			}
		}()
	}
	// DDL scheduler
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-t.C:
			}
			now := time.Now()
			m.mu.Lock()
			for _, b := range m.blocks {
				if b.done || b.queued {
					continue
				}
				if now.Sub(b.t0) >= m.ddl {
					b.queued = true
					m.decodeQ <- b
				}
			}
			m.mu.Unlock()
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
	// store symbol
	p := make([]byte, len(data))
	copy(p, data)
	b.syms[esi] = p
	m.inUse.Add(int64(len(p)))
	m.mu.Unlock()

	// feed decoder; if innovative, bump haveU
	if inc, _ := b.dec.AddSymbol(uint32(esi), p); inc {
		b.haveU++
		if b.haveU >= b.K && !b.queued {
			b.queued = true
			m.decodeQ <- b
		}
	}
	return true
}

func (m *rxManager) closeAndFinalize(expectedSHA [32]byte) (string, error) {
	close(m.stopCh)
	close(m.decodeQ)
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
		return "", errors.New("sha256 mismatch")
	}
	if err := os.Rename(m.tmpPath, finalPath); err != nil {
		return "", err
	}
	return finalPath, nil
}
