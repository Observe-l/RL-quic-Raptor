package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/logging"
)

type rawConnStats struct {
	sentLongPkts      atomic.Uint64
	sentLongBytes     atomic.Uint64
	sentShortPkts     atomic.Uint64
	sentShortBytes    atomic.Uint64
	acked1RTTPkts     atomic.Uint64
	lost1RTTPkts      atomic.Uint64
	lostHandshakePkts atomic.Uint64
	lostInitialPkts   atomic.Uint64

	lastSRTTNanos      atomic.Int64
	lastMinRTTNanos    atomic.Int64
	lastLatestRTTNanos atomic.Int64
	lastCWNDBytes      atomic.Uint64
	lastInFlightBytes  atomic.Uint64
	lastInFlightPkts   atomic.Int64
	seenMetrics        atomic.Bool
}

func newRawConnStats() *rawConnStats { return &rawConnStats{} }

func newRawConnStatsTracer(s *rawConnStats) *logging.ConnectionTracer {
	if s == nil {
		return nil
	}
	var once sync.Once
	return &logging.ConnectionTracer{
		SentLongHeaderPacket: func(_ *logging.ExtendedHeader, size logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			s.sentLongPkts.Add(1)
			s.sentLongBytes.Add(uint64(size))
		},
		SentShortHeaderPacket: func(_ *logging.ShortHeader, size logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			s.sentShortPkts.Add(1)
			s.sentShortBytes.Add(uint64(size))
		},
		UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
			once.Do(func() { s.seenMetrics.Store(true) })
			if rttStats != nil {
				srtt := rttStats.SmoothedRTT()
				if srtt > 0 {
					s.lastSRTTNanos.Store(srtt.Nanoseconds())
				}
				minRTT := rttStats.MinRTT()
				if minRTT > 0 {
					s.lastMinRTTNanos.Store(minRTT.Nanoseconds())
				}
				latest := rttStats.LatestRTT()
				if latest > 0 {
					s.lastLatestRTTNanos.Store(latest.Nanoseconds())
				}
			}
			if cwnd >= 0 {
				s.lastCWNDBytes.Store(uint64(cwnd))
			}
			if bytesInFlight >= 0 {
				s.lastInFlightBytes.Store(uint64(bytesInFlight))
			}
			s.lastInFlightPkts.Store(int64(packetsInFlight))
		},
		AcknowledgedPacket: func(enc logging.EncryptionLevel, _ logging.PacketNumber) {
			if enc == logging.Encryption1RTT {
				s.acked1RTTPkts.Add(1)
			}
		},
		LostPacket: func(enc logging.EncryptionLevel, _ logging.PacketNumber, _ logging.PacketLossReason) {
			switch enc {
			case logging.Encryption1RTT:
				s.lost1RTTPkts.Add(1)
			case logging.EncryptionHandshake:
				s.lostHandshakePkts.Add(1)
			case logging.EncryptionInitial:
				s.lostInitialPkts.Add(1)
			}
		},
	}
}

func (s *rawConnStats) Format(prefix string) string {
	sentLongPkts := s.sentLongPkts.Load()
	sentLongBytes := s.sentLongBytes.Load()
	sentShortPkts := s.sentShortPkts.Load()
	sentShortBytes := s.sentShortBytes.Load()
	acked1RTT := s.acked1RTTPkts.Load()
	lost1RTT := s.lost1RTTPkts.Load()
	lostHS := s.lostHandshakePkts.Load()
	lostInit := s.lostInitialPkts.Load()

	metricsTail := ""
	if s.seenMetrics.Load() {
		srtt := time.Duration(s.lastSRTTNanos.Load())
		minRTT := time.Duration(s.lastMinRTTNanos.Load())
		latest := time.Duration(s.lastLatestRTTNanos.Load())
		srttMS := int64(0)
		if srtt > 0 {
			srttMS = srtt.Milliseconds()
		}
		minMS := int64(0)
		if minRTT > 0 {
			minMS = minRTT.Milliseconds()
		}
		latestMS := int64(0)
		if latest > 0 {
			latestMS = latest.Milliseconds()
		}
		metricsTail = fmt.Sprintf(" srtt_ms=%d min_rtt_ms=%d latest_rtt_ms=%d cwnd_bytes=%d inflight_bytes=%d inflight_pkts=%d",
			srttMS,
			minMS,
			latestMS,
			s.lastCWNDBytes.Load(),
			s.lastInFlightBytes.Load(),
			s.lastInFlightPkts.Load(),
		)
	}

	sentPkts := sentLongPkts + sentShortPkts
	sentBytes := sentLongBytes + sentShortBytes

	return fmt.Sprintf("%s sent_pkts=%d sent_bytes=%d sent_long_pkts=%d sent_long_bytes=%d sent_short_pkts=%d sent_short_bytes=%d acked_1rtt_pkts=%d lost_1rtt_pkts=%d lost_handshake_pkts=%d lost_initial_pkts=%d%s",
		prefix,
		sentPkts, sentBytes,
		sentLongPkts, sentLongBytes,
		sentShortPkts, sentShortBytes,
		acked1RTT, lost1RTT, lostHS, lostInit,
		metricsTail,
	)
}
