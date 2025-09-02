package fecquic

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	IngressRing int           // ring size (power of two), default 4096
}

func (o *RXOptions) setDefaults() {
	if o.BudgetBytes <= 0 {
		o.BudgetBytes = 10 * 1024 * 1024
	}
	if o.DDL <= 0 {
		o.DDL = 50 * time.Millisecond
	}
	if o.Workers <= 0 {
		o.Workers = max(runtime.NumCPU()-1, 1)
	}
	if o.IngressRing <= 0 {
		o.IngressRing = 4096
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
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
	syms map[int]*slab
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
	tmpPath string
	written atomic.Uint64

	// metrics
	decBlocks    atomic.Int64
	decTimeTotal atomic.Int64 // ms (coarse)
	dropsRepairs atomic.Int64
	dropsSystem  atomic.Int64
	// finer-grained metrics
	ringDropRepairs   atomic.Int64 // ring full -> repair dropped at ingest
	ringDropSystem    atomic.Int64 // ring full -> systematic dropped at ingest
	budgetDropRepairs atomic.Int64 // budget pressure -> repair dropped at classify
	dupSymbols        atomic.Int64 // duplicates discarded in classify
	dropAfterQRep     atomic.Int64 // symbol dropped because block already queued/done (repair)
	dropAfterQSys     atomic.Int64 // symbol dropped because block already queued/done (systematic)
	addSymCount       atomic.Int64 // number of AddSymbol() calls
	addSymTimeMs      atomic.Int64 // total time spent in AddSymbol() in ms
	addSymTimeUs      atomic.Int64 // total time spent in AddSymbol() in µs
	decodeAttempts    atomic.Int64 // number of Decode() attempts
	decodeFailures    atomic.Int64 // Decode() returned !ok or error
	queuedByDDL       atomic.Int64 // blocks queued due to DDL expiry
	queuedByReady     atomic.Int64 // blocks queued when haveU >= K
	readyBlocks       atomic.Int64 // blocks reaching haveU >= K
	readyTimeMs       atomic.Int64 // sum of time-to-ready (ms)
	readyTimeUs       atomic.Int64 // sum of time-to-ready (µs)
	ingressProcMs     atomic.Int64
	ingressProcUs     atomic.Int64
	classifyProcMs    atomic.Int64
	classifyProcUs    atomic.Int64
	writeTimeMs       atomic.Int64
	writeTimeUs       atomic.Int64

	// ingress ring and slabs
	ring  *mpscRing
	slabs *sync.Pool
}

// Symbol carries one symbol into the classifier pipeline.
type Symbol struct {
	BlockID  uint16
	ESI      int
	N, K, L  int
	DataSize int
	IsRepair bool
	Arrival  int64 // nano timestamp
	Buf      []byte
	slab     *slab
}

// slab wraps a reusable byte buffer with recorded length used.
type slab struct {
	b []byte
	n int
}

// mpscRing: multiple producers, single consumer ring buffer for Symbols.
type mpscRing struct {
	buf  []Symbol
	mask uint64
	head atomic.Uint64 // consumer index
	tail atomic.Uint64 // producer index
}

func newRing(capacity int) *mpscRing {
	// round up to power of two
	n := 1
	for n < capacity {
		n <<= 1
	}
	return &mpscRing{buf: make([]Symbol, n), mask: uint64(n - 1)}
}

func (r *mpscRing) tryPush(x Symbol) bool {
	for {
		tail := r.tail.Load()
		head := r.head.Load()
		if tail-head >= uint64(len(r.buf)) {
			return false // full
		}
		// attempt to claim slot by CAS tail
		if r.tail.CompareAndSwap(tail, tail+1) {
			r.buf[tail&r.mask] = x
			return true
		}
		// retry
	}
}

// tryPopBatch returns up to max items; caller is the single consumer.
func (r *mpscRing) tryPopBatch(dst []Symbol) int {
	head := r.head.Load()
	tail := r.tail.Load()
	n := int(tail - head)
	if n <= 0 {
		return 0
	}
	if n > len(dst) {
		n = len(dst)
	}
	for i := 0; i < n; i++ {
		dst[i] = r.buf[(head+uint64(i))&r.mask]
	}
	r.head.Store(head + uint64(n))
	return n
}

// RXStats carries aggregated metrics from rxManager.
type RXStats struct {
	DecBlocks         int64
	DecMS             int64
	DecUS             int64
	DropRepairs       int64
	DropSystem        int64
	RingDropRepairs   int64
	RingDropSystem    int64
	BudgetDropRepairs int64
	Duplicates        int64
	DropAfterQRep     int64
	DropAfterQSys     int64
	AddSymCalls       int64
	AddSymMS          int64
	AddSymUS          int64
	DecodeAttempts    int64
	DecodeFailures    int64
	QueuedByDDL       int64
	QueuedByReady     int64
	ReadyBlocks       int64
	ReadyTimeMS       int64
	ReadyTimeUS       int64
	IngressMS         int64
	IngressUS         int64
	ClassifyMS        int64
	ClassifyUS        int64
	WriteMS           int64
	WriteUS           int64
	InUseBytes        int64
	RingSize          int
	RingCap           int
}

func (m *rxManager) Stats() RXStats {
	// approximate ring depth by tail-head
	var rs int
	if m.ring != nil {
		head := m.ring.head.Load()
		tail := m.ring.tail.Load()
		rs = int(tail - head)
		if rs < 0 {
			rs = 0
		}
		if rs > len(m.ring.buf) {
			rs = len(m.ring.buf)
		}
	}
	return RXStats{
		DecBlocks:         m.decBlocks.Load(),
		DecMS:             m.decTimeTotal.Load(),
		DecUS:             0, // not tracked per-call; kept 0 for now
		DropRepairs:       m.dropsRepairs.Load(),
		DropSystem:        m.dropsSystem.Load(),
		RingDropRepairs:   m.ringDropRepairs.Load(),
		RingDropSystem:    m.ringDropSystem.Load(),
		BudgetDropRepairs: m.budgetDropRepairs.Load(),
		Duplicates:        m.dupSymbols.Load(),
		DropAfterQRep:     m.dropAfterQRep.Load(),
		DropAfterQSys:     m.dropAfterQSys.Load(),
		AddSymCalls:       m.addSymCount.Load(),
		AddSymMS:          m.addSymTimeMs.Load(),
		AddSymUS:          m.addSymTimeUs.Load(),
		DecodeAttempts:    m.decodeAttempts.Load(),
		DecodeFailures:    m.decodeFailures.Load(),
		QueuedByDDL:       m.queuedByDDL.Load(),
		QueuedByReady:     m.queuedByReady.Load(),
		ReadyBlocks:       m.readyBlocks.Load(),
		ReadyTimeMS:       m.readyTimeMs.Load(),
		ReadyTimeUS:       m.readyTimeUs.Load(),
		IngressMS:         m.ingressProcMs.Load(),
		IngressUS:         m.ingressProcUs.Load(),
		ClassifyMS:        m.classifyProcMs.Load(),
		ClassifyUS:        m.classifyProcUs.Load(),
		WriteMS:           m.writeTimeMs.Load(),
		WriteUS:           m.writeTimeUs.Load(),
		InUseBytes:        m.inUse.Load(),
		RingSize:          rs,
		RingCap:           len(m.ring.buf),
	}
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
	m.ring = newRing(rx.IngressRing)
	// slab pool sized to L bytes; callers slice to used size
	m.slabs = &sync.Pool{New: func() any { return &slab{b: make([]byte, L)} }}
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
			t0 := time.Now()
			_, _ = m.out.WriteAt(data, w.off)
			d := time.Since(t0)
			m.writeTimeMs.Add(d.Milliseconds())
			m.writeTimeUs.Add(d.Microseconds())
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
				m.decodeAttempts.Add(1)
				t0 := time.Now()
				ok, bytes, err := b.dec.Decode()
				if err != nil || !ok {
					// decoding failed; likely need more symbols
					m.decodeFailures.Add(1)
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
				for _, s := range b.syms {
					m.inUse.Add(int64(-s.n))
					// return buffer to pool
					s.n = 0
					m.slabs.Put(s)
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
		m.queuedByDDL.Add(1)
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
	// Classifier: pop from ring in batches and update blocks (non-blocking ingress)
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		const batch = 64
		buf := make([]Symbol, batch)
		for {
			select {
			case <-m.stopCh:
				return
			default:
			}
			n := m.ring.tryPopBatch(buf)
			if n == 0 {
				time.Sleep(1 * time.Millisecond)
				continue
			}
			t0 := time.Now()
			for i := 0; i < n; i++ {
				s := buf[i]
				// admission: drop repair if over budget
				cur := m.inUse.Load()
				if int(cur)+len(s.Buf) > m.budget && s.IsRepair {
					m.dropsRepairs.Add(1)
					m.budgetDropRepairs.Add(1)
					continue
				}
				// get or create block
				m.mu.Lock()
				b := m.blocks[s.BlockID]
				if b == nil {
					b = &rxBlock{id: s.BlockID, t0: time.Now(), K: s.K, N: s.N, L: s.L, dataSize: s.DataSize, syms: make(map[int]*slab, s.N)}
					dec, err := fec.NewRaptorQDecoder(s.DataSize, s.L)
					if err != nil {
						m.mu.Unlock()
						continue
					}
					b.dec = dec
					m.blocks[s.BlockID] = b
				}
				// If already queued for decode or done, drop incoming symbols to avoid racing decoder.
				if b.queued || b.done {
					m.mu.Unlock()
					// release slab immediately
					s.slab.n = 0
					m.slabs.Put(s.slab)
					if s.IsRepair {
						m.dropAfterQRep.Add(1)
					} else {
						m.dropAfterQSys.Add(1)
						m.dropsSystem.Add(1)
					}
					continue
				}
				if _, ok := b.syms[s.ESI]; ok {
					m.mu.Unlock()
					// duplicate; release slab
					s.slab.n = 0
					m.slabs.Put(s.slab)
					m.dupSymbols.Add(1)
					continue
				}
				b.syms[s.ESI] = s.slab
				m.inUse.Add(int64(len(s.Buf)))
				m.mu.Unlock()
				// feed decoder
				tAdd := time.Now()
				inc, _ := b.dec.AddSymbol(uint32(s.ESI), s.Buf)
				m.addSymTimeMs.Add(time.Since(tAdd).Milliseconds())
				m.addSymTimeUs.Add(time.Since(tAdd).Microseconds())
				m.addSymCount.Add(1)
				if inc {
					b.haveU++
					if b.haveU >= b.K && !b.queued {
						// record time-to-ready once
						m.readyBlocks.Add(1)
						m.readyTimeMs.Add(time.Since(b.t0).Milliseconds())
						m.readyTimeUs.Add(time.Since(b.t0).Microseconds())
						b.queued = true
						m.queuedByReady.Add(1)
						m.decodeQ <- b
					}
				}
			}
			d := time.Since(t0)
			m.classifyProcMs.Add(d.Milliseconds())
			m.classifyProcUs.Add(d.Microseconds())
		}
	}()
}

// ingest one symbol; returns whether enqueued into ingress ring.
func (m *rxManager) ingest(blockID uint16, esi int, N, K, L int, data []byte, dataSize int) bool {
	t0 := time.Now()
	isRepair := esi >= K
	// copy into an owned buffer (avoid holding references to network buffers)
	sp := m.slabs.Get().(*slab)
	if cap(sp.b) < len(data) {
		sp.b = make([]byte, L)
	}
	sp.n = len(data)
	p := sp.b[:sp.n]
	copy(p, data)
	s := Symbol{
		BlockID:  blockID,
		ESI:      esi,
		N:        N,
		K:        K,
		L:        L,
		DataSize: dataSize,
		IsRepair: isRepair,
		Arrival:  time.Now().UnixNano(),
		Buf:      p,
		slab:     sp,
	}
	ok := m.ring.tryPush(s)
	if !ok {
		if isRepair {
			m.dropsRepairs.Add(1)
			m.ringDropRepairs.Add(1)
		} else {
			m.dropsSystem.Add(1)
			m.ringDropSystem.Add(1)
		}
		// return buffer to pool on drop
		sp.n = 0
		m.slabs.Put(sp)
		return false
	}
	d := time.Since(t0)
	m.ingressProcMs.Add(d.Milliseconds())
	m.ingressProcUs.Add(d.Microseconds())
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
