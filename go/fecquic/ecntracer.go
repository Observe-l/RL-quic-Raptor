package fecquic

import (
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/logging"
)

// ECNStats collects basic ECN counters for one connection.
type ECNStats struct {
	start time.Time

	TxECT0 atomic.Uint64
	TxECT1 atomic.Uint64
	RxECT0 atomic.Uint64
	RxECT1 atomic.Uint64
	RxCE   atomic.Uint64
}

func NewECNStats() *ECNStats { return &ECNStats{start: time.Now()} }

// Snapshot returns cumulative counts.
func (s *ECNStats) Snapshot() (tx0, tx1, rx0, rx1, rxce uint64, since time.Duration) {
	return s.TxECT0.Load(), s.TxECT1.Load(), s.RxECT0.Load(), s.RxECT1.Load(), s.RxCE.Load(), time.Since(s.start)
}

// NewECNConnTracer returns a ConnectionTracer that updates stats for ECN marks.
func NewECNConnTracer(stats *ECNStats) *logging.ConnectionTracer {
	if stats == nil {
		stats = NewECNStats()
	}
	return &logging.ConnectionTracer{
		// We count ECN on 1-RTT (short header) packets primarily. Long header counting is harmless.
		SentShortHeaderPacket: func(_ *logging.ShortHeader, _ logging.ByteCount, ecn logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			switch ecn { //nolint:exhaustive
			case logging.ECT0:
				stats.TxECT0.Add(1)
			case logging.ECT1:
				stats.TxECT1.Add(1)
			}
		},
		ReceivedShortHeaderPacket: func(_ *logging.ShortHeader, _ logging.ByteCount, ecn logging.ECN, _ []logging.Frame) {
			switch ecn { //nolint:exhaustive
			case logging.ECT0:
				stats.RxECT0.Add(1)
			case logging.ECT1:
				stats.RxECT1.Add(1)
			case logging.ECNCE:
				stats.RxCE.Add(1)
			}
		},
		SentLongHeaderPacket: func(_ *logging.ExtendedHeader, _ logging.ByteCount, ecn logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			switch ecn { //nolint:exhaustive
			case logging.ECT0:
				stats.TxECT0.Add(1)
			case logging.ECT1:
				stats.TxECT1.Add(1)
			}
		},
		ReceivedLongHeaderPacket: func(_ *logging.ExtendedHeader, _ logging.ByteCount, ecn logging.ECN, _ []logging.Frame) {
			switch ecn { //nolint:exhaustive
			case logging.ECT0:
				stats.RxECT0.Add(1)
			case logging.ECT1:
				stats.RxECT1.Add(1)
			case logging.ECNCE:
				stats.RxCE.Add(1)
			}
		},
	}
}
