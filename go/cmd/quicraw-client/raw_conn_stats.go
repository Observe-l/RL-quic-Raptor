package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/logging"
)

type rawByteInterval struct {
	start uint64
	end   uint64
}

type rawConnStats struct {
	sentLongPkts      atomic.Uint64
	sentLongBytes     atomic.Uint64
	sentShortPkts     atomic.Uint64
	sentShortBytes    atomic.Uint64
	acked1RTTPkts     atomic.Uint64
	lost1RTTPkts      atomic.Uint64
	lostHandshakePkts atomic.Uint64
	lostInitialPkts   atomic.Uint64
	retx1RTTPkts      atomic.Uint64
	retx1RTTBytes     atomic.Uint64

	// Loss-recovery / retransmission-trigger style counters.
	// These are closer to an "ARQ rounds / requests" metric than byte-based retransmission counters.
	lossTimerExpiredACK       atomic.Uint64
	lossTimerExpiredPTO       atomic.Uint64
	lossTimerExpiredPathProbe atomic.Uint64
	// lossDetectionEvents attempts to count "recovery trigger rounds" that originate
	// from loss detection (ACK-based / time-threshold) as opposed to timer expirations.
	// It is coalesced from LostPacket callbacks using a small time window.
	lossDetectionEvents     atomic.Uint64
	lastLossEventUnixNanos  atomic.Int64
	ptoEvents                atomic.Uint64
	lastPTOCount              atomic.Uint32

	lastSRTTNanos      atomic.Int64
	lastMinRTTNanos    atomic.Int64
	lastLatestRTTNanos atomic.Int64
	lastCWNDBytes      atomic.Uint64
	lastInFlightBytes  atomic.Uint64
	lastInFlightPkts   atomic.Int64
	seenMetrics        atomic.Bool

	streamMu         sync.Mutex
	streamSentRanges map[logging.StreamID][]rawByteInterval
}

func newRawConnStats() *rawConnStats {
	return &rawConnStats{streamSentRanges: make(map[logging.StreamID][]rawByteInterval)}
}

func (s *rawConnStats) addStreamRangeAndCountOverlap(streamID logging.StreamID, start, end uint64) uint64 {
	if start >= end {
		return 0
	}
	s.streamMu.Lock()
	defer s.streamMu.Unlock()

	intervals := s.streamSentRanges[streamID]
	// intervals are kept sorted and non-overlapping.
	var overlap uint64
	for _, iv := range intervals {
		if iv.end <= start {
			continue
		}
		if iv.start >= end {
			break
		}
		os := iv.start
		if os < start {
			os = start
		}
		oe := iv.end
		if oe > end {
			oe = end
		}
		if oe > os {
			overlap += oe - os
		}
	}

	// Merge [start,end) into intervals.
	merged := make([]rawByteInterval, 0, len(intervals)+1)
	cur := rawByteInterval{start: start, end: end}
	inserted := false
	for _, iv := range intervals {
		if iv.end < cur.start {
			merged = append(merged, iv)
			continue
		}
		if cur.end < iv.start {
			if !inserted {
				merged = append(merged, cur)
				inserted = true
			}
			merged = append(merged, iv)
			continue
		}
		// overlap or adjacent: merge
		if iv.start < cur.start {
			cur.start = iv.start
		}
		if iv.end > cur.end {
			cur.end = iv.end
		}
	}
	if !inserted {
		merged = append(merged, cur)
	}
	s.streamSentRanges[streamID] = merged

	return overlap
}

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
		SentShortHeaderPacket: func(_ *logging.ShortHeader, size logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, frames []logging.Frame) {
			s.sentShortPkts.Add(1)
			s.sentShortBytes.Add(uint64(size))

			// Estimate retransmissions by tracking overlap of STREAM frame byte ranges.
			// This is tailored for the quic-raw file transfer which sends (mostly) a single stream.
			var pktRetxBytes uint64
			for _, f := range frames {
				sf, ok := f.(*logging.StreamFrame)
				if !ok || sf == nil {
					continue
				}
				if sf.Length <= 0 {
					continue
				}
				start := uint64(sf.Offset)
				end := start + uint64(sf.Length)
				pktRetxBytes += s.addStreamRangeAndCountOverlap(sf.StreamID, start, end)
			}
			if pktRetxBytes > 0 {
				s.retx1RTTPkts.Add(1)
				s.retx1RTTBytes.Add(pktRetxBytes)
			}
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
				// Coalesce loss detection callbacks into "events".
				now := time.Now().UnixNano()
				gap := int64(time.Millisecond)
				if srtt := s.lastSRTTNanos.Load(); srtt > 0 {
					g := srtt / 4
					if g < int64(time.Millisecond) {
						g = int64(time.Millisecond)
					}
					if g > int64(20*time.Millisecond) {
						g = int64(20 * time.Millisecond)
					}
					gap = g
				}
				last := s.lastLossEventUnixNanos.Load()
				if last == 0 || now-last > gap {
					s.lossDetectionEvents.Add(1)
				}
				s.lastLossEventUnixNanos.Store(now)
			case logging.EncryptionHandshake:
				s.lostHandshakePkts.Add(1)
			case logging.EncryptionInitial:
				s.lostInitialPkts.Add(1)
			}
		},
		UpdatedPTOCount: func(value uint32) {
			// quic-go calls this with:
			// - an increasing counter on each PTO (Probe Timeout) expiration
			// - 0 when the PTO counter resets
			last := s.lastPTOCount.Load()
			if value > last {
				s.ptoEvents.Add(uint64(value - last))
			}
			s.lastPTOCount.Store(value)
		},
		LossTimerExpired: func(timerType logging.TimerType, _ logging.EncryptionLevel) {
			switch timerType {
			case logging.TimerTypeACK:
				s.lossTimerExpiredACK.Add(1)
			case logging.TimerTypePTO:
				s.lossTimerExpiredPTO.Add(1)
			case logging.TimerTypePathProbe:
				s.lossTimerExpiredPathProbe.Add(1)
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
	retx1RTT := s.retx1RTTPkts.Load()
	retx1RTTBytes := s.retx1RTTBytes.Load()

	lteACK := s.lossTimerExpiredACK.Load()
	ltePTO := s.lossTimerExpiredPTO.Load()
	lteProbe := s.lossTimerExpiredPathProbe.Load()
	ptoEvents := s.ptoEvents.Load()
	recoveryTriggers := lteACK + ltePTO + lteProbe
	lossDetectionEvents := s.lossDetectionEvents.Load()

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

	return fmt.Sprintf("%s sent_pkts=%d sent_bytes=%d sent_long_pkts=%d sent_long_bytes=%d sent_short_pkts=%d sent_short_bytes=%d acked_1rtt_pkts=%d lost_1rtt_pkts=%d lost_handshake_pkts=%d lost_initial_pkts=%d retx_1rtt_pkts=%d retx_1rtt_bytes=%d recovery_triggers=%d loss_detection_events=%d loss_timer_expired_ack=%d loss_timer_expired_pto=%d loss_timer_expired_path_probe=%d pto_events=%d%s",
		prefix,
		sentPkts, sentBytes,
		sentLongPkts, sentLongBytes,
		sentShortPkts, sentShortBytes,
		acked1RTT, lost1RTT, lostHS, lostInit,
		retx1RTT, retx1RTTBytes,
		recoveryTriggers,
		lossDetectionEvents,
		lteACK,
		ltePTO,
		lteProbe,
		ptoEvents,
		metricsTail,
	)
}
