package congestion

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// bbrv2Sender is an experimental, simplified BBRv2-inspired congestion controller.
//
// Notes / constraints:
// - This implementation is designed for controlled lab evaluation with QUIC-FEC.
// - It is NOT a full RFC / production-grade BBRv2.
// - It intentionally avoids reacting strongly to random i.i.d. loss (unlike Reno/CUBIC).
// - Bandwidth sampling is simplified because we don't have a full delivery-rate sampler here.
//
// State machine loosely follows BBRv2/BBR: Startup -> Drain -> ProbeBW.
// ProbeRTT is omitted.

type bbrMode uint8

const (
	bbrStartup bbrMode = iota
	bbrDrain
	bbrProbeBW
)

var probeBWGainCycle = []float64{1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0}

const (
	startupPacingGain = 2.885
	drainPacingGain   = 1.0 / startupPacingGain
	cwndGain          = 2.0
	minCwndPackets    = 4
	maxPacingRateBps  = uint64(10_000_000_000 / 8) // 10 Gbps in bytes/s cap
)

type bbrv2Sender struct {
	clock   Clock
	rtt     *utils.RTTStats
	tracer  *logging.ConnectionTracer
	lastQlg logging.CongestionState

	pacer *pacer

	maxDatagramSize protocol.ByteCount

	mode       bbrMode
	cycleIndex int
	cycleStart time.Time

	// Model
	minRTT time.Duration
	// maxBw is a max filter of our simplified delivery-rate samples.
	maxBw Bandwidth

	pacingGain float64

	cwnd protocol.ByteCount

	// Ack sampling (windowed; avoids ACK-compression spikes)
	sampleStart time.Time
	sampleAcked protocol.ByteCount

	// Round-trip tracking (for startup exit heuristic)
	nextRoundEnd protocol.PacketNumber
	roundStarted bool

	fullBw      Bandwidth
	fullBwCount int

	largestSent              protocol.PacketNumber
	largestAcked             protocol.PacketNumber
	largestSentAtLastCutback protocol.PacketNumber

	// Debug emission (throttled)
	lastDebugTime time.Time
	lastDebugBw   Bandwidth
}

var (
	_ SendAlgorithm               = &bbrv2Sender{}
	_ SendAlgorithmWithDebugInfos = &bbrv2Sender{}
)

func NewBBRv2Sender(clock Clock, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount, tracer *logging.ConnectionTracer) *bbrv2Sender {
	s := &bbrv2Sender{
		clock:                    clock,
		rtt:                      rttStats,
		tracer:                   tracer,
		maxDatagramSize:          initialMaxDatagramSize,
		mode:                     bbrStartup,
		pacingGain:               startupPacingGain,
		maxBw:                    0,
		fullBw:                   0,
		largestSent:              protocol.InvalidPacketNumber,
		largestAcked:             protocol.InvalidPacketNumber,
		nextRoundEnd:             protocol.InvalidPacketNumber,
		largestSentAtLastCutback: protocol.InvalidPacketNumber,
	}
	// Initial cwnd similar to quic-go defaults.
	s.cwnd = initialCwndPackets() * initialMaxDatagramSize
	s.pacer = newPacer(s.bandwidthEstimateForPacer)
	if s.tracer != nil && s.tracer.UpdatedCongestionState != nil {
		s.lastQlg = logging.CongestionStateSlowStart
		s.tracer.UpdatedCongestionState(logging.CongestionStateSlowStart)
	}
	return s
}

func (b *bbrv2Sender) bandwidthEstimateForPacer() Bandwidth {
	// pacer expects bits/s.
	bw := b.pacingBandwidth()
	if bw == 0 {
		return infBandwidth
	}
	return bw
}

func (b *bbrv2Sender) pacingBandwidth() Bandwidth {
	// maxBw already in bits/s (Bandwidth).
	bw := b.maxBw
	if bw == 0 || bw == infBandwidth {
		return infBandwidth
	}
	// Apply pacing gain.
	g := b.pacingGain
	if g <= 0 {
		g = 1.0
	}
	scaled := uint64(float64(bw) * g)
	// Cap to avoid overflow.
	maxBits := maxPacingRateBps * 8
	if scaled > maxBits {
		scaled = maxBits
	}
	return Bandwidth(scaled)
}

func (b *bbrv2Sender) TimeUntilSend(_ protocol.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrv2Sender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrv2Sender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	b.maxDatagramSize = s
	b.pacer.SetMaxDatagramSize(s)
	if b.cwnd < b.minCwnd() {
		b.cwnd = b.minCwnd()
	}
}

func (b *bbrv2Sender) minCwnd() protocol.ByteCount {
	return b.maxDatagramSize * minCwndPackets
}

func (b *bbrv2Sender) GetCongestionWindow() protocol.ByteCount {
	return b.cwnd
}

func (b *bbrv2Sender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.cwnd
}

func (b *bbrv2Sender) InSlowStart() bool {
	return b.mode == bbrStartup
}

func (b *bbrv2Sender) InRecovery() bool {
	return b.largestAcked != protocol.InvalidPacketNumber && b.largestAcked <= b.largestSentAtLastCutback
}

func (b *bbrv2Sender) MaybeExitSlowStart() {
	// No-op: BBR doesn't use HyStart. Startup exit happens via bandwidth plateau.
}

func (b *bbrv2Sender) OnPacketSent(sentTime time.Time, _ protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	b.largestSent = packetNumber
	if !b.roundStarted {
		b.roundStarted = true
		b.nextRoundEnd = packetNumber
	}
}

func (b *bbrv2Sender) OnPacketAcked(ackedPacketNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
	b.largestAcked = max(ackedPacketNumber, b.largestAcked)

	// Update RTT model.
	min := b.rtt.MinRTT()
	if min > 0 {
		b.minRTT = min
	}
	if b.minRTT <= 0 {
		// Fallback to SRTT if MinRTT not available yet.
		if srtt := b.rtt.SmoothedRTT(); srtt > 0 {
			b.minRTT = srtt
		} else {
			b.minRTT = 50 * time.Millisecond
		}
	}

	// Delivery-rate sampling (windowed). We aggregate ACKed bytes over a fixed window
	// to reduce the impact of ACK compression (which can make per-ACK deltas tiny and
	// produce unrealistically large samples).
	if b.sampleStart.IsZero() {
		b.sampleStart = eventTime
		b.sampleAcked = 0
	}
	if ackedBytes > 0 {
		b.sampleAcked += ackedBytes
	}
	// 50ms window gives a stable estimate even on high RTT paths.
	const win = 50 * time.Millisecond
	if eventTime.After(b.sampleStart) && eventTime.Sub(b.sampleStart) >= win {
		delta := eventTime.Sub(b.sampleStart)
		if delta > 0 && b.sampleAcked > 0 {
			sample := BandwidthFromDelta(b.sampleAcked, delta)
			if sample > b.maxBw {
				b.maxBw = sample
			}
		}
		b.sampleStart = eventTime
		b.sampleAcked = 0
	}

	// Emit sender-side bandwidth estimate for RL / harness merging.
	b.maybeDebugEstimate(eventTime)

	// Round tracking for Startup exit.
	newRound := false
	if b.roundStarted && ackedPacketNumber > b.nextRoundEnd {
		newRound = true
		b.nextRoundEnd = b.largestSent
	}

	if b.mode == bbrStartup && newRound {
		b.checkFullBandwidthReached()
		if b.fullBwCount >= 3 {
			b.enterDrain()
		}
	}

	if b.mode == bbrDrain {
		// Exit Drain once inflight is at or below BDP.
		if priorInFlight <= b.bdpBytes() {
			b.enterProbeBW(eventTime)
		}
	}

	if b.mode == bbrProbeBW {
		b.maybeAdvanceGainCycle(eventTime)
	}

	b.updateCwnd(priorInFlight)
}

// BandwidthEstimate returns the current sender-side delivery rate estimate.
// This is intended for logging / debugging / RL observation.
func (b *bbrv2Sender) BandwidthEstimate() Bandwidth {
	if b.maxBw == 0 {
		return infBandwidth
	}
	return b.maxBw
}

func (b *bbrv2Sender) maybeDebugEstimate(now time.Time) {
	if b.tracer == nil || b.tracer.Debug == nil {
		return
	}
	// Throttle to reduce log volume.
	if !b.lastDebugTime.IsZero() && now.Sub(b.lastDebugTime) < 200*time.Millisecond {
		return
	}
	bw := b.BandwidthEstimate()
	if bw == b.lastDebugBw {
		return
	}
	b.lastDebugTime = now
	b.lastDebugBw = bw

	mode := "startup"
	switch b.mode {
	case bbrStartup:
		mode = "startup"
	case bbrDrain:
		mode = "drain"
	case bbrProbeBW:
		mode = "probebw"
	}

	bwMbps := 0.0
	if bw != 0 && bw != infBandwidth {
		bwMbps = float64(bw) / 1e6
	}
	pacing := b.pacingBandwidth()
	pacingMbps := 0.0
	if pacing != 0 && pacing != infBandwidth {
		pacingMbps = float64(pacing) / 1e6
	}

	// msg is JSON (kept small; parsed by scripts/quicfec_run_once.sh)
	b.tracer.Debug("cc-estimate", fmt.Sprintf("{\"algo\":\"bbrv2\",\"mode\":\"%s\",\"bw_mbps\":%.6f,\"pacing_bw_mbps\":%.6f}", mode, bwMbps, pacingMbps))
}

func (b *bbrv2Sender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, _ protocol.ByteCount) {
	// BBRv2 is not loss-based. We only mark recovery to avoid runaway on persistent loss.
	if packetNumber <= b.largestSentAtLastCutback {
		return
	}
	b.largestSentAtLastCutback = b.largestSent
	if b.tracer != nil && b.tracer.UpdatedCongestionState != nil {
		b.tracer.UpdatedCongestionState(logging.CongestionStateRecovery)
		b.lastQlg = logging.CongestionStateRecovery
	}
	_ = lostBytes
	// Keep cwnd as-is (bounded by minCwnd).
	if b.cwnd < b.minCwnd() {
		b.cwnd = b.minCwnd()
	}
}

func (b *bbrv2Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	// Reset model on RTO-like event.
	b.mode = bbrStartup
	b.pacingGain = startupPacingGain
	b.cycleIndex = 0
	b.fullBw = 0
	b.fullBwCount = 0
	b.maxBw = 0
	b.sampleStart = time.Time{}
	b.sampleAcked = 0
	b.roundStarted = false
	b.nextRoundEnd = protocol.InvalidPacketNumber
	b.largestSentAtLastCutback = protocol.InvalidPacketNumber
	b.cwnd = max(b.minCwnd(), initialCwndPackets()*b.maxDatagramSize)
	if b.tracer != nil && b.tracer.UpdatedCongestionState != nil {
		b.tracer.UpdatedCongestionState(logging.CongestionStateSlowStart)
		b.lastQlg = logging.CongestionStateSlowStart
	}
}

func (b *bbrv2Sender) checkFullBandwidthReached() {
	bw := b.maxBw
	if bw == 0 || bw == infBandwidth {
		return
	}
	if b.fullBw == 0 {
		b.fullBw = bw
		b.fullBwCount = 0
		return
	}
	// If bandwidth hasn't grown by 25% over a round, count it.
	if float64(bw) < float64(b.fullBw)*1.25 {
		b.fullBwCount++
		return
	}
	b.fullBw = bw
	b.fullBwCount = 0
}

func (b *bbrv2Sender) enterDrain() {
	b.mode = bbrDrain
	b.pacingGain = drainPacingGain
	if b.tracer != nil && b.tracer.UpdatedCongestionState != nil {
		b.tracer.UpdatedCongestionState(logging.CongestionStateCongestionAvoidance)
		b.lastQlg = logging.CongestionStateCongestionAvoidance
	}
}

func (b *bbrv2Sender) enterProbeBW(now time.Time) {
	b.mode = bbrProbeBW
	b.cycleIndex = 0
	b.cycleStart = now
	b.pacingGain = probeBWGainCycle[b.cycleIndex]
	if b.tracer != nil && b.tracer.UpdatedCongestionState != nil {
		b.tracer.UpdatedCongestionState(logging.CongestionStateCongestionAvoidance)
		b.lastQlg = logging.CongestionStateCongestionAvoidance
	}
}

func (b *bbrv2Sender) maybeAdvanceGainCycle(now time.Time) {
	if b.minRTT <= 0 {
		return
	}
	if b.cycleStart.IsZero() {
		b.cycleStart = now
		return
	}
	if now.Sub(b.cycleStart) < b.minRTT {
		return
	}
	b.cycleIndex = (b.cycleIndex + 1) % len(probeBWGainCycle)
	b.cycleStart = now
	b.pacingGain = probeBWGainCycle[b.cycleIndex]
}

func (b *bbrv2Sender) bdpBytes() protocol.ByteCount {
	if b.maxBw == 0 || b.maxBw == infBandwidth {
		return b.cwnd
	}
	bwBytesPerSec := uint64(b.maxBw / BytesPerSecond)
	if bwBytesPerSec == 0 {
		return b.cwnd
	}
	bdp := (protocol.ByteCount(bwBytesPerSec) * protocol.ByteCount(b.minRTT.Nanoseconds())) / 1e9
	if bdp < b.minCwnd() {
		bdp = b.minCwnd()
	}
	return bdp
}

func (b *bbrv2Sender) updateCwnd(priorInFlight protocol.ByteCount) {
	bdp := b.bdpBytes()
	target := protocol.ByteCount(float64(bdp) * cwndGain)
	if target < b.minCwnd() {
		target = b.minCwnd()
	}
	// Keep cwnd at least at inflight to avoid stalling on ack compression.
	if target < priorInFlight {
		target = priorInFlight
	}
	b.cwnd = target
}
