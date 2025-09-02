package fecquic

import (
	"testing"
	"time"
)

// Test that TryPush on a full ring is fast and non-blocking.
func TestMPSCRingTryPushNonBlocking(t *testing.T) {
	r := newRing(8)
	// Fill the ring
	for i := 0; i < 8; i++ {
		ok := r.tryPush(Symbol{ESI: i})
		if !ok {
			t.Fatalf("unexpected full at %d", i)
		}
	}
	// Now it should be full, subsequent pushes should fail quickly
	const iters = 2000
	start := time.Now()
	slow := 0
	for i := 0; i < iters; i++ {
		t0 := time.Now()
		ok := r.tryPush(Symbol{ESI: i})
		if ok {
			t.Fatalf("push succeeded on full ring at %d", i)
		}
		if time.Since(t0) > 200*time.Microsecond {
			slow++
		}
	}
	dur := time.Since(start)
	t.Logf("avg=%.1fns slow=%d/%d total=%s", float64(dur.Nanoseconds())/iters, slow, iters, dur)
}

// Test that rxManager.ingest remains fast under ring saturation (non-blocking ingress path).
func TestRXIngestNonBlockingWhenRingFull(t *testing.T) {
	rx := RXOptions{BudgetBytes: 1 << 20, DDL: 50 * time.Millisecond, Workers: 0, IngressRing: 8}
	m, err := newRXManager(1024, 0, 256, t.TempDir(), "test", rx)
	if err != nil {
		t.Fatal(err)
	}
	// Fill ring directly to capacity using ingest
	payload := make([]byte, 256)
	for i := 0; i < 8; i++ {
		if !m.ingest(0, i, 8, 4, 256, payload, 256) {
			t.Fatalf("unexpected ingest failure at %d", i)
		}
	}
	// Now measure failed ingests are quick
	const iters = 500
	slow := 0
	for i := 0; i < iters; i++ {
		t0 := time.Now()
		_ = m.ingest(0, 1000+i, 8, 4, 256, payload, 256)
		if time.Since(t0) > 250*time.Microsecond {
			slow++
		}
	}
	if slow > iters/10 {
		t.Fatalf("too many slow ingests: %d/%d", slow, iters)
	}
}

// Test that under tight budget, only repairs are dropped by classifier.
func TestRXBudgetDropsRepairs(t *testing.T) {
	rx := RXOptions{BudgetBytes: 3 * 1024, DDL: 50 * time.Millisecond, Workers: 1, IngressRing: 256}
	m, err := newRXManager(4096, 0, 256, t.TempDir(), "test", rx)
	if err != nil {
		t.Fatal(err)
	}
	m.start(rx)
	defer func() {
		close(m.stopCh)
		close(m.decodeQ)
		close(m.writeQ)
		m.wg.Wait()
		_ = m.out.Close()
	}()

	// Send K=6 systematic symbols for block 0
	payload := make([]byte, 256)
	K := 6
	for i := 0; i < K; i++ {
		if !m.ingest(0, i, 12, K, 256, payload, 1536) {
			t.Fatalf("ingest systematic failed at %d", i)
		}
	}
	// Now flood with repairs to exceed budget; classifier should drop repairs.
	for i := 0; i < 2000; i++ {
		_ = m.ingest(0, K+i, 12, K, 256, payload, 1536)
	}
	time.Sleep(50 * time.Millisecond)
	if m.dropsRepairs.Load() == 0 {
		t.Fatalf("expected some repair drops, got 0")
	}
	if m.dropsSystem.Load() != 0 {
		t.Fatalf("unexpected systematic drops: %d", m.dropsSystem.Load())
	}
}
