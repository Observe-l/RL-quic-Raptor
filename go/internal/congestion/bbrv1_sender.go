package congestion

import (
	"fmt"
	"os"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/logging"
)

// bbrv1Sender is a BBRv1-style congestion controller.
//
// Notes:
// - This is BBRv1-style (with a simple loss/timeout guard), NOT BBRv2.
// - Keeps the high-level model: delivery-rate sampling, Startup/Drain/ProbeBW/ProbeRTT.
// - quic-go doesn't expose an explicit "cwnd blocked" signal to CC. We approximate it using bytesInFlight.
type bbrv1Sender struct {
	clock  Clock
	rtt    *utils.RTTStats
	tracer *logging.ConnectionTracer

	maxDatagramSize protocol.ByteCount
	pacer           *pacer

	// CC state
	state bbrv1State

	pacingGain float64
	cwndGain   float64

	// BBR model signals
	// btlBw is bottleneck bandwidth (max-filtered), in bits/s.
	btlBw Bandwidth
	// bwEstimate is the last delivery-rate sample, in bits/s.
	bwEstimate Bandwidth

	// BtlBw max-filter (per round).
	btlBwFilter [bbrv1BtlBwFilterLen]Bandwidth
	fullBw      Bandwidth
	fullBwCount int
	filledPipe  bool

	// RTprop (min RTT) tracking.
	rtProp       time.Duration
	rtPropStamp  time.Time
	rtPropExpire bool

	// Gain cycle.
	cycleIndex  int
	cycleStamp  time.Time
	cycleOnLoss bool

	// ProbeRTT.
	probeRTTDoneStamp time.Time
	probeRTTRoundDone bool
	priorCwnd         protocol.ByteCount
	priorInFlight     protocol.ByteCount
	idleRestart       bool

	// Recovery / loss reaction.
	packetConservation       bool
	lossIntervalStart        time.Time
	lastLossWasTimeout       bool
	lossBytesInInterval      protocol.ByteCount
	lossEventsInInterval     int
	largestSent              protocol.PacketNumber
	largestAcked             protocol.PacketNumber
	largestSentAtLastCutback protocol.PacketNumber

	// Windowed delivery-rate sampler state (ported from picoquic/frames.c estimate_path_bandwidth).
	delivered             uint64
	deliveredSentLast     time.Time
	deliveredTimeLast     time.Time
	deliveredLimited      bool
	lastSampleCwndLimited bool

	// Round tracking (ported from picoquic/bbr.c BBRUpdateBtlBw).
	nextRoundDelivered uint64
	roundStart         bool

	// Controller outputs.
	cwnd          protocol.ByteCount
	pacingRateBps Bandwidth // bits/s, for the pacer
	sendQuantum   protocol.ByteCount

	// Internal bytes-in-flight tracking (to approximate bytes_in_transit).
	bytesInFlight protocol.ByteCount

	// Per-packet sampler bookkeeping.
	sentPackets map[protocol.PacketNumber]bbrv1SentInfo

	// Debug emission (throttled).
	lastDebugTime time.Time
	lastDebugBw   Bandwidth
}

func (b *bbrv1Sender) flecCompatEnabled() bool {
	// When enabled, approximate picoquic's BBRv1 "loss fixes":
	// - filter repeated loss events to once per RTT-ish interval
	// - on sustained loss, cut cwnd (and set cycleOnLoss)
	// This is useful for apples-to-apples comparison vs picoquic/bbr.c.
	return os.Getenv("QUIC_FEC_BBRV1_FLEC_COMPAT") == "1"
}

func (b *bbrv1Sender) lossFilterInterval() time.Duration {
	// picoquic uses smoothed_rtt. Use SRTT if available, else RTProp, else a conservative fallback.
	if srtt := b.rtt.SmoothedRTT(); srtt > 0 {
		return srtt
	}
	if b.rtProp > 0 {
		return b.rtProp
	}
	return 100 * time.Millisecond
}

func (b *bbrv1Sender) maybeFlecCompatReactToLoss(now time.Time, isTimeout bool) {
	if !b.flecCompatEnabled() {
		return
	}

	interval := b.lossFilterInterval()
	if !b.lossIntervalStart.IsZero() {
		// Filter repeated loss events (similar to picoquic_bbr_notify_congestion).
		if now.Before(b.lossIntervalStart.Add(interval)) && (!isTimeout || b.lastLossWasTimeout) {
			return
		}
		if b.cycleOnLoss && (!isTimeout || b.lastLossWasTimeout) {
			return
		}
	}

	// Decide whether to apply a cwnd cut.
	// picoquic gates this on picoquic_hystart_loss_test(). We don't have that signal,
	// so we approximate it using a per-interval loss budget.
	applyCut := isTimeout
	if !applyCut {
		// A conservative sustained-loss heuristic: if we lost a non-trivial fraction of cwnd
		// over a loss interval, treat it as congestion.
		if b.lossBytesInInterval >= b.cwnd/4 || b.lossEventsInInterval >= 3 {
			applyCut = true
		}
	}
	if !applyCut {
		return
	}

	// Apply cwnd cut.
	if isTimeout {
		b.cwnd = b.minPipeCwnd()
	} else {
		b.cwnd = max(b.minPipeCwnd(), b.cwnd/2)
	}

	b.lossIntervalStart = now
	b.lastLossWasTimeout = isTimeout
	b.lossBytesInInterval = 0
	b.lossEventsInInterval = 0

	// Coordinate with the BBR state machine (mirrors picoquic behavior).
	if b.state == bbrv1Startup {
		b.filledPipe = true
		b.enterDrain()
	} else {
		b.cycleOnLoss = true
	}
}

type bbrv1State uint8

const (
	bbrv1Startup bbrv1State = iota
	bbrv1Drain
	bbrv1ProbeBW
	bbrv1ProbeRTT
)

const (
	bbrv1BtlBwFilterLen = 10

	bbrv1HighGain           = 2.8853900817779 // 2/ln(2)
	bbrv1MinPipeCwndPackets = 4

	bbrv1ProbeRTTInterval = 10 * time.Second
	bbrv1ProbeRTTDuration = 200 * time.Millisecond

	bbrv1PacingRateLowBps    = 150000.0  // bytes/s
	bbrv1PacingRateMediumBps = 3000000.0 // bytes/s

	bbrv1BandwidthMinInterval = time.Millisecond
)

var bbrv1PacingGainCycle = []float64{1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.25, 0.75}

type bbrv1SentInfo struct {
	sentTime time.Time
	size     protocol.ByteCount

	// delivery-rate sampler snapshot at send.
	deliveredPrior     uint64
	deliveredTimePrior time.Time
	deliveredSentPrior time.Time

	// Whether this packet was sent while CWND-limited (approximation of picoquic's cwin_blocked signal).
	cwndLimited bool
	// Whether this sample is path/app-limited.
	pathLimited bool
}

var (
	_ SendAlgorithm               = &bbrv1Sender{}
	_ SendAlgorithmWithDebugInfos = &bbrv1Sender{}
)

func NewBBRV1Sender(clock Clock, rttStats *utils.RTTStats, initialMaxDatagramSize protocol.ByteCount, tracer *logging.ConnectionTracer) *bbrv1Sender {
	s := &bbrv1Sender{
		clock:                    clock,
		rtt:                      rttStats,
		tracer:                   tracer,
		maxDatagramSize:          initialMaxDatagramSize,
		sentPackets:              make(map[protocol.PacketNumber]bbrv1SentInfo, 2048),
		largestSent:              protocol.InvalidPacketNumber,
		largestAcked:             protocol.InvalidPacketNumber,
		largestSentAtLastCutback: protocol.InvalidPacketNumber,
	}
	// Initial cwnd similar to quic-go defaults.
	s.cwnd = initialCongestionWindow * initialMaxDatagramSize
	s.pacer = newPacer(s.bandwidthEstimateForPacer)
	s.pacer.SetMaxDatagramSize(initialMaxDatagramSize)

	s.enterStartup()
	// Initialize RTprop stamp.
	now := s.clock.Now()
	s.rtPropStamp = now
	s.cycleStamp = now

	return s
}

func (b *bbrv1Sender) bandwidthEstimateForPacer() Bandwidth {
	bw := b.pacingRateBps
	if bw == 0 {
		return infBandwidth
	}
	return bw
}

func (b *bbrv1Sender) TimeUntilSend(_ protocol.ByteCount) time.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrv1Sender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

func (b *bbrv1Sender) SetMaxDatagramSize(s protocol.ByteCount) {
	if s < b.maxDatagramSize {
		panic(fmt.Sprintf("congestion BUG: decreased max datagram size from %d to %d", b.maxDatagramSize, s))
	}
	b.maxDatagramSize = s
	b.pacer.SetMaxDatagramSize(s)
	if b.cwnd < b.minPipeCwnd() {
		b.cwnd = b.minPipeCwnd()
	}
}

func (b *bbrv1Sender) minPipeCwnd() protocol.ByteCount {
	return b.maxDatagramSize * bbrv1MinPipeCwndPackets
}

func (b *bbrv1Sender) GetCongestionWindow() protocol.ByteCount {
	return b.cwnd
}

func (b *bbrv1Sender) CanSend(bytesInFlight protocol.ByteCount) bool {
	return bytesInFlight < b.cwnd
}

func (b *bbrv1Sender) InSlowStart() bool {
	return b.state == bbrv1Startup
}

func (b *bbrv1Sender) InRecovery() bool {
	return b.largestAcked != protocol.InvalidPacketNumber && b.largestAcked <= b.largestSentAtLastCutback
}

func (b *bbrv1Sender) MaybeExitSlowStart() {
	// No-op: Startup exit is based on full pipe detection.
}

func (b *bbrv1Sender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytes)
	// NOTE: quic-go's sent_packet_handler passes isAckEliciting here.
	// Non-ACK-eliciting packets (ACK-only) are not included in bytes_in_flight and
	// will never be ACKed. We must ignore them, otherwise we leak bytesInFlight and
	// per-packet sampler state and can get stuck in Drain/ProbeRTT.
	isAckEliciting := isRetransmittable
	if !isAckEliciting {
		return
	}
	b.largestSent = packetNumber
	b.bytesInFlight += bytes

	// bytesInFlight passed in from quic-go already includes this packet.
	cwndLimited := bytesInFlight >= b.cwnd
	pathLimited := !cwndLimited

	b.sentPackets[packetNumber] = bbrv1SentInfo{
		sentTime:           sentTime,
		size:               bytes,
		deliveredPrior:     b.delivered,
		deliveredTimePrior: b.deliveredTimeLast,
		deliveredSentPrior: b.deliveredSentLast,
		cwndLimited:        cwndLimited,
		pathLimited:        pathLimited,
	}
}

func (b *bbrv1Sender) OnPacketAcked(ackedPacketNumber protocol.PacketNumber, ackedBytes protocol.ByteCount, _ protocol.ByteCount, eventTime time.Time) {
	b.largestAcked = max(ackedPacketNumber, b.largestAcked)
	if ackedBytes > b.bytesInFlight {
		b.bytesInFlight = 0
	} else {
		b.bytesInFlight -= ackedBytes
	}

	// Exit recovery once all packets sent at the last cutback are acknowledged.
	// This mirrors the quic-go CUBIC sender's recovery bookkeeping and is the only
	// recovery signal we have via this interface.
	if b.packetConservation && !b.InRecovery() {
		b.packetConservation = false
	}

	// Update RTprop (min RTT) from RTTStats.
	if minRTT := b.rtt.MinRTT(); minRTT > 0 {
		if b.rtProp == 0 || minRTT < b.rtProp {
			b.rtProp = minRTT
		}
	}
	if b.rtProp == 0 {
		// Conservative fallback.
		if srtt := b.rtt.SmoothedRTT(); srtt > 0 {
			b.rtProp = srtt
		} else {
			b.rtProp = 100 * time.Millisecond
		}
	}

	// Update delivered counter and run delivery-rate sampling.
	if ackedBytes > 0 {
		b.delivered += uint64(ackedBytes)
	}
	info, ok := b.sentPackets[ackedPacketNumber]
	if ok {
		delete(b.sentPackets, ackedPacketNumber)
		b.estimateBandwidthSample(info, eventTime)
		// Round tracking uses the delivered counter snapshot carried per packet.
		b.updateRound(info.deliveredPrior)
	}

	// Update model and state machine (similar to picoquic_bbr_notify bw_measurement path).
	b.updateModelAndState(eventTime)
	b.updateControlParameters(ackedBytes)

	b.maybeDebugEstimate(eventTime)
}

func (b *bbrv1Sender) OnCongestionEvent(packetNumber protocol.PacketNumber, lostBytes, _ protocol.ByteCount) {
	if packetNumber <= b.largestSentAtLastCutback {
		return
	}
	b.largestSentAtLastCutback = b.largestSent

	// Track loss volume for the optional flec-compat sustained-loss heuristic.
	// (Done before early returns and independent of recovery mode.)
	if lostBytes > 0 {
		b.lossBytesInInterval += lostBytes
		b.lossEventsInInterval++
	}

	// Remove from in-flight accounting.
	if lostBytes > b.bytesInFlight {
		b.bytesInFlight = 0
	} else {
		b.bytesInFlight -= lostBytes
	}

	// Optional: emulate picoquic's BBRv1 loss reaction for fair comparison.
	b.maybeFlecCompatReactToLoss(b.clock.Now(), false /* isTimeout */)

	// BBRv1 is not loss-based (no Reno-style multiplicative decrease), but it does
	// enter a recovery mode and uses packet conservation.
	//
	// Enter recovery + packet conservation.
	// Note: we intentionally do NOT apply Reno/CUBIC-style multiplicative decrease.
	// Also, we don't reduce cwnd by lostBytes here. QUIC reduces bytes_in_flight when
	// a packet is declared lost, which naturally creates room to send replacements.
	// Packet conservation will bound sending to what is delivered.
	if b.tracer != nil && b.tracer.UpdatedCongestionState != nil {
		b.tracer.UpdatedCongestionState(logging.CongestionStateRecovery)
	}
	b.packetConservation = true
	if b.cwnd < b.minPipeCwnd() {
		b.cwnd = b.minPipeCwnd()
	}
}

func (b *bbrv1Sender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if !packetsRetransmitted {
		return
	}
	now := b.clock.Now()
	if b.flecCompatEnabled() {
		// picoquic's bbr.c reacts to timeout by reducing cwnd strongly, without fully
		// resetting the BBR model. Keep behavior closer to picoquic when requested.
		b.maybeFlecCompatReactToLoss(now, true /* isTimeout */)
		return
	}
	// Default behavior: reset to a safe startup state.
	b.notifyCongestion(now, true /* isTimeout */)
}

func (b *bbrv1Sender) notifyCongestion(now time.Time, isTimeout bool) {
	if !isTimeout {
		return
	}

	// Conservative timeout reaction: reset the model and restart.
	// Keep cwnd bounded by a small floor, to allow recovery probes.
	b.cwnd = max(b.minPipeCwnd(), b.cwnd/2)

	// Reset key model signals.
	b.btlBw = 0
	b.bwEstimate = 0
	for i := range b.btlBwFilter {
		b.btlBwFilter[i] = 0
	}
	b.fullBw = 0
	b.fullBwCount = 0
	b.filledPipe = false
	b.cycleOnLoss = false
	b.cycleIndex = 0
	b.cycleStamp = now
	b.pacingRateBps = 0

	b.enterStartup()
	b.lossIntervalStart = now
	b.lastLossWasTimeout = true
}

func (b *bbrv1Sender) estimateBandwidthSample(info bbrv1SentInfo, ackTime time.Time) {
	// Mirror picoquic/frames.c estimate_path_bandwidth.
	if !b.deliveredSentLast.IsZero() && info.sentTime.Before(b.deliveredSentLast) {
		return
	}

	if b.deliveredTimeLast.IsZero() {
		b.deliveredTimeLast = ackTime
		b.deliveredSentLast = info.sentTime
		b.lastSampleCwndLimited = info.cwndLimited
		b.deliveredLimited = info.pathLimited
		return
	}

	// If the packet didn't carry prior timestamps (early in the connection), fall back to last refs.
	deliveredTimePrior := info.deliveredTimePrior
	if deliveredTimePrior.IsZero() {
		deliveredTimePrior = b.deliveredTimeLast
	}
	deliveredSentPrior := info.deliveredSentPrior
	if deliveredSentPrior.IsZero() {
		deliveredSentPrior = b.deliveredSentLast
	}

	recvInterval := ackTime.Sub(deliveredTimePrior)
	sendInterval := info.sentTime.Sub(deliveredSentPrior)
	interval := recvInterval
	if sendInterval > interval {
		interval = sendInterval
	}
	if interval < bbrv1BandwidthMinInterval {
		return
	}

	delta := b.delivered - info.deliveredPrior
	if delta == 0 {
		return
	}
	sample := BandwidthFromDelta(protocol.ByteCount(delta), interval)
	if !info.pathLimited || sample > b.bwEstimate {
		b.bwEstimate = sample
	}

	// Update refs.
	b.deliveredTimeLast = ackTime
	b.deliveredSentLast = info.sentTime
	b.lastSampleCwndLimited = info.cwndLimited
	b.deliveredLimited = info.pathLimited
}

func (b *bbrv1Sender) updateRound(deliveredPrior uint64) {
	if deliveredPrior >= b.nextRoundDelivered {
		b.nextRoundDelivered = b.delivered
		b.roundStart = true
	} else {
		b.roundStart = false
	}
}

func (b *bbrv1Sender) updateBtlBw() {
	// BBRv1 only trusts samples if CWND was probed entirely; we approximate using cwndLimited-at-send.
	if b.bwEstimate == 0 || b.bwEstimate == infBandwidth {
		return
	}
	if !b.lastSampleCwndLimited {
		return
	}
	if b.roundStart {
		// Shift by 1 and compute max over remaining rounds.
		var mx Bandwidth
		for i := bbrv1BtlBwFilterLen - 2; i >= 0; i-- {
			v := b.btlBwFilter[i]
			b.btlBwFilter[i+1] = v
			if v > mx {
				mx = v
			}
		}
		b.btlBwFilter[0] = 0
		b.btlBw = mx
	}
	if b.bwEstimate > b.btlBwFilter[0] {
		b.btlBwFilter[0] = b.bwEstimate
		if b.bwEstimate > b.btlBw {
			b.btlBw = b.bwEstimate
		}
	}
}

func (b *bbrv1Sender) updateRTprop(now time.Time) {
	b.rtPropExpire = now.After(b.rtPropStamp.Add(bbrv1ProbeRTTInterval))
	if b.rtPropExpire {
		// We don't have one-way RTT samples; rely on RTTStats minRTT.
		// When expired, we force ProbeRTT to refresh.
	}
}

func (b *bbrv1Sender) isNextCyclePhase(now time.Time) bool {
	if b.rtProp <= 0 {
		return false
	}
	isFullLength := b.cycleOnLoss || now.Sub(b.cycleStamp) > b.rtProp
	if b.pacingGain != 1.0 {
		if b.pacingGain > 1.0 {
			isFullLength = isFullLength && (b.cycleOnLoss || b.priorInFlight >= b.inflight(b.pacingGain))
		} else {
			isFullLength = isFullLength || (b.priorInFlight <= b.inflight(1.0))
		}
	}
	return isFullLength
}

func (b *bbrv1Sender) advanceCyclePhase(now time.Time) {
	b.cycleOnLoss = false
	b.cycleStamp = now
	b.cycleIndex++
	if b.cycleIndex >= len(bbrv1PacingGainCycle) {
		start := int(float64(b.rtProp) / float64(100*time.Millisecond))
		if start > 5 {
			start = 5
		}
		if start < 0 {
			start = 0
		}
		b.cycleIndex = start
	}
	b.pacingGain = bbrv1PacingGainCycle[b.cycleIndex]
}

func (b *bbrv1Sender) checkCyclePhase(now time.Time) {
	if b.state == bbrv1ProbeBW && b.isNextCyclePhase(now) {
		b.advanceCyclePhase(now)
	}
}

func (b *bbrv1Sender) checkFullPipe() {
	if b.filledPipe || !b.roundStart || b.deliveredLimited {
		return
	}
	if b.fullBw == 0 {
		b.fullBw = b.btlBw
		b.fullBwCount = 0
		return
	}
	if float64(b.btlBw) >= float64(b.fullBw)*1.25 {
		b.fullBw = b.btlBw
		b.fullBwCount = 0
		return
	}
	b.fullBwCount++
	if b.fullBwCount >= 3 {
		b.filledPipe = true
	}
}

func (b *bbrv1Sender) checkDrain(now time.Time) {
	if b.state == bbrv1Startup && b.filledPipe {
		b.enterDrain()
	}
	if b.state == bbrv1Drain && b.bytesInFlight <= b.inflight(1.0) {
		b.enterProbeBW(now)
	}
}

func (b *bbrv1Sender) enterStartup() {
	b.state = bbrv1Startup
	b.pacingGain = bbrv1HighGain
	b.cwndGain = bbrv1HighGain
}

func (b *bbrv1Sender) enterDrain() {
	b.state = bbrv1Drain
	b.pacingGain = 1.0 / bbrv1HighGain
	b.cwndGain = bbrv1HighGain
}

func (b *bbrv1Sender) enterProbeBW(now time.Time) {
	b.state = bbrv1ProbeBW
	b.pacingGain = 1.0
	b.cwndGain = 1.5
	b.cycleIndex = 4
	b.advanceCyclePhase(now)
}

func (b *bbrv1Sender) enterProbeRTT() {
	b.state = bbrv1ProbeRTT
	b.pacingGain = 1.0
	b.cwndGain = 1.0
}

func (b *bbrv1Sender) exitProbeRTT(now time.Time) {
	if b.filledPipe {
		b.enterProbeBW(now)
	} else {
		b.enterStartup()
	}
}

func (b *bbrv1Sender) checkProbeRTT(now time.Time) {
	if b.state != bbrv1ProbeRTT && b.rtPropExpire && !b.idleRestart {
		b.enterProbeRTT()
		b.priorCwnd = b.saveCwnd()
		b.probeRTTDoneStamp = time.Time{}
		b.probeRTTRoundDone = false
	}

	if b.state != bbrv1ProbeRTT {
		return
	}

	// HandleProbeRTT.
	if b.probeRTTDoneStamp.IsZero() && b.bytesInFlight <= b.minPipeCwnd() {
		b.probeRTTDoneStamp = now.Add(bbrv1ProbeRTTDuration)
		b.probeRTTRoundDone = false
		b.nextRoundDelivered = b.delivered
	} else if !b.probeRTTDoneStamp.IsZero() {
		if b.roundStart {
			b.probeRTTRoundDone = true
		}
		if b.probeRTTRoundDone && now.After(b.probeRTTDoneStamp) {
			b.rtPropStamp = now
			b.restoreCwnd()
			b.exitProbeRTT(now)
			b.idleRestart = false
		}
	}
}

func (b *bbrv1Sender) updateModelAndState(now time.Time) {
	// Update bottleneck estimate based on latest delivery-rate sample.
	b.updateBtlBw()
	// Gain cycle.
	b.checkCyclePhase(now)
	// Startup exit.
	b.checkFullPipe()
	// Drain / ProbeBW transitions.
	b.checkDrain(now)
	// RTprop expiry & ProbeRTT.
	b.updateRTprop(now)
	b.checkProbeRTT(now)
}

func (b *bbrv1Sender) setPacingRateWithGain(pacingGain float64) {
	if b.btlBw == 0 || b.btlBw == infBandwidth {
		return
	}
	// Convert bottleneck bandwidth to bytes/s.
	bwBytesPerSec := float64(b.btlBw) / float64(BytesPerSecond)
	rateBytesPerSec := pacingGain * bwBytesPerSec
	rateBps := Bandwidth(rateBytesPerSec * 8.0)
	if b.filledPipe || rateBps > b.pacingRateBps {
		b.pacingRateBps = rateBps
	}
}

func (b *bbrv1Sender) setPacingRate() {
	b.setPacingRateWithGain(b.pacingGain)
}

func (b *bbrv1Sender) setSendQuantum() {
	// Port of BBRSetSendQuantum.
	if b.pacingRateBps == 0 || b.pacingRateBps == infBandwidth {
		b.sendQuantum = b.maxDatagramSize
		return
	}
	rateBytesPerSec := float64(b.pacingRateBps) / float64(BytesPerSecond)
	if rateBytesPerSec < bbrv1PacingRateLowBps {
		b.sendQuantum = b.maxDatagramSize
		return
	}
	if rateBytesPerSec < bbrv1PacingRateMediumBps {
		b.sendQuantum = 2 * b.maxDatagramSize
		return
	}
	q := protocol.ByteCount(rateBytesPerSec * 0.001) // 1ms worth of bytes
	if q > 64000 {
		q = 64000
	}
	if q < b.maxDatagramSize {
		q = b.maxDatagramSize
	}
	b.sendQuantum = q
}

func (b *bbrv1Sender) inflight(gain float64) protocol.ByteCount {
	if b.btlBw == 0 || b.btlBw == infBandwidth || b.rtProp <= 0 {
		return b.cwnd
	}
	bwBytesPerSec := float64(b.btlBw) / float64(BytesPerSecond)
	bdpBytes := bwBytesPerSec * b.rtProp.Seconds()
	quanta := float64(3 * b.sendQuantum)
	target := gain*bdpBytes + quanta
	min := float64(b.minPipeCwnd())
	if target < min {
		target = min
	}
	if target > float64(^protocol.ByteCount(0)) {
		target = float64(^protocol.ByteCount(0))
	}
	return protocol.ByteCount(target)
}

func (b *bbrv1Sender) updateTargetCwnd() protocol.ByteCount {
	return b.inflight(b.cwndGain)
}

func (b *bbrv1Sender) modulateCwndForRecovery(bytesDelivered protocol.ByteCount) {
	if b.packetConservation {
		if b.cwnd < b.bytesInFlight+bytesDelivered {
			b.cwnd = b.bytesInFlight + bytesDelivered
		}
	}
}

func (b *bbrv1Sender) modulateCwndForProbeRTT() {
	if b.state == bbrv1ProbeRTT {
		if b.cwnd > b.minPipeCwnd() {
			b.cwnd = b.minPipeCwnd()
		}
	}
}

func (b *bbrv1Sender) updateControlParameters(bytesDelivered protocol.ByteCount) {
	b.setPacingRate()
	b.setSendQuantum()
	// target cwnd and cwnd modulation.
	target := b.updateTargetCwnd()
	if b.packetConservation {
		// Packet conservation (BBRv1): allow sending only as bytes are delivered.
		// This keeps the pipe full but avoids over-injection during recovery.
		if b.cwnd < b.bytesInFlight+bytesDelivered {
			b.cwnd = b.bytesInFlight + bytesDelivered
		}
		if b.cwnd < b.minPipeCwnd() {
			b.cwnd = b.minPipeCwnd()
		}
	} else {
		if b.filledPipe {
			b.cwnd += bytesDelivered
			if b.cwnd > target {
				b.cwnd = target
			}
		} else if b.cwnd < target || b.delivered < uint64(initialCongestionWindow*b.maxDatagramSize) {
			b.cwnd += bytesDelivered
			if b.cwnd < b.minPipeCwnd() {
				b.cwnd = b.minPipeCwnd()
			}
		}
	}
	b.modulateCwndForProbeRTT()

	// Remember inflight for next cycle checks.
	b.priorInFlight = b.bytesInFlight
}

func (b *bbrv1Sender) saveCwnd() protocol.ByteCount {
	w := b.cwnd
	if (b.packetConservation || b.state == bbrv1ProbeBW) && b.cwnd < b.priorCwnd {
		w = b.priorCwnd
	}
	return w
}

func (b *bbrv1Sender) restoreCwnd() {
	if b.cwnd < b.priorCwnd {
		b.cwnd = b.priorCwnd
	}
}

func (b *bbrv1Sender) maybeDebugEstimate(now time.Time) {
	if b.tracer == nil || b.tracer.Debug == nil {
		return
	}
	if !b.lastDebugTime.IsZero() && now.Sub(b.lastDebugTime) < 200*time.Millisecond {
		return
	}
	if b.btlBw == 0 || b.btlBw == b.lastDebugBw {
		return
	}
	b.lastDebugTime = now
	b.lastDebugBw = b.btlBw

	mode := "startup"
	switch b.state {
	case bbrv1Startup:
		mode = "startup"
	case bbrv1Drain:
		mode = "drain"
	case bbrv1ProbeBW:
		mode = "probebw"
	case bbrv1ProbeRTT:
		mode = "probertt"
	}

	bwMbps := 0.0
	if b.btlBw != 0 && b.btlBw != infBandwidth {
		bwMbps = float64(b.btlBw) / 1e6
	}
	pacingMbps := 0.0
	if b.pacingRateBps != 0 && b.pacingRateBps != infBandwidth {
		pacingMbps = float64(b.pacingRateBps) / 1e6
	}

	b.tracer.Debug("cc-estimate", fmt.Sprintf("{\"algo\":\"bbrv1\",\"mode\":\"%s\",\"bw_mbps\":%.6f,\"pacing_bw_mbps\":%.6f}", mode, bwMbps, pacingMbps))
}
