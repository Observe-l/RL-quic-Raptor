package congestion

// This file contains the small compatibility layer needed to adapt the
// complete BBRv2 implementation imported from SagerNet/sing-quic to this
// quic-go fork. The upstream implementation lives in the same conceptual
// congestion-control layer, but this fork predates its extended congestion
// event interface.

import (
	"math"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// These aliases keep the imported BBRv2 code close to its original form.
type ByteCount = protocol.ByteCount
type PacketNumber = protocol.PacketNumber

// AckedPacketInfo and LostPacketInfo describe one congestion event. BBRv2
// needs the complete ACK/loss batch in order to perform delivery-rate and
// round-trip sampling correctly.
type AckedPacketInfo struct {
	PacketNumber PacketNumber
	BytesAcked   ByteCount
	ReceivedTime time.Time
	SentTime     time.Time
}

type LostPacketInfo struct {
	PacketNumber PacketNumber
	BytesLost    ByteCount
}

// SendAlgorithmEx is optional. Existing congestion controllers continue to
// use SendAlgorithm; the full BBRv2 implementation opts into this interface.
type SendAlgorithmEx interface {
	SendAlgorithm
	OnCongestionEventEx(priorInFlight ByteCount, eventTime time.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo, ecnCE int64)
	OnPacketsLost(leastUnacked PacketNumber)
	OnAppLimited(bytesInFlight ByteCount)
}

// PacingRateProvider exposes the current sender pacing rate in bits per
// second. It is intentionally optional: QUIC can continue to use congestion
// controllers that don't expose a directly readable pacing rate.
type PacingRateProvider interface {
	PacingRateBps() uint64
}

// CongestionControlEx is kept as an alias for the terminology used by the
// imported implementation.
type CongestionControlEx = SendAlgorithmEx

// NewBBRv2Sender preserves the constructor used by this fork while routing
// creation to the complete BBRv2 sender imported from SagerNet.
func NewBBRv2Sender(clock Clock, rttStats *utils.RTTStats, initialMaxDatagramSize ByteCount, tracer *logging.ConnectionTracer) *BBR2Sender {
	initialCwnd := ByteCount(initialCongestionWindow) * initialMaxDatagramSize
	initialRtt := 100 * time.Millisecond
	if rttStats != nil {
		if srtt := rttStats.SmoothedRTT(); srtt > 0 {
			initialRtt = srtt
		} else if minRtt := rttStats.MinRTT(); minRtt > 0 {
			initialRtt = minRtt
		}
	}
	s := newBBR2SenderWithInitialRTT(clock, initialMaxDatagramSize, initialCwnd, false, initialRtt)
	if rttStats != nil {
		s.SetRTTStatsProvider(rttStats)
	}
	s.tracer = tracer
	return s
}

// RTTStatsProvider is the optional RTT interface used by the imported code.
// The current QUIC RTTStats implementation satisfies it.
type RTTStatsProvider interface {
	MinRTT() time.Duration
	LatestRTT() time.Duration
	SmoothedRTT() time.Duration
	MeanDeviation() time.Duration
	MaxAckDelay() time.Duration
	PTO(includeMaxAckDelay bool) time.Duration
	UpdateRTT(sendDelta, ackDelay time.Duration)
	SetMaxAckDelay(mad time.Duration)
	SetInitialRTT(t time.Duration)
}

func BandwidthFromBytesAndTimeDelta(bytes ByteCount, delta time.Duration) Bandwidth {
	if delta <= 0 {
		return infBandwidth
	}
	return BandwidthFromDelta(bytes, delta)
}

func BandwidthFromBytesPerSecond(bytesPerSecond uint64) Bandwidth {
	if bytesPerSecond > math.MaxUint64/uint64(BytesPerSecond) {
		return infBandwidth
	}
	return Bandwidth(bytesPerSecond * uint64(BytesPerSecond))
}

func (b Bandwidth) ToBytesPerSecond() uint64 {
	return uint64(b) / uint64(BytesPerSecond)
}

func (b Bandwidth) ToBytesPerPeriod(period time.Duration) ByteCount {
	if period <= 0 || b == 0 {
		return 0
	}
	return ByteCount(uint64(b) * uint64(period) / uint64(time.Second) / uint64(BytesPerSecond))
}

func (b Bandwidth) Mul(factor float64) Bandwidth {
	if factor <= 0 || b == 0 {
		return 0
	}
	if b == infBandwidth || factor >= float64(math.MaxUint64)/float64(b) {
		return infBandwidth
	}
	return Bandwidth(float64(b) * factor)
}

func (b Bandwidth) IsZero() bool {
	return b == 0
}

func (b Bandwidth) IsInfinite() bool {
	return b == infBandwidth
}

func BytesFromBandwidthAndTimeDelta(bandwidth Bandwidth, delta time.Duration) ByteCount {
	return bandwidth.ToBytesPerPeriod(delta)
}
