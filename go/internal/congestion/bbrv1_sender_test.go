package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time { return c.t }

func TestBBRv1SenderBandwidthSamplingSetsBtlBw(t *testing.T) {
	clk := &testClock{t: time.Unix(0, 0)}
	rttStats := &utils.RTTStats{}
	// Provide a minRTT sample.
	rttStats.UpdateRTT(50*time.Millisecond, 0)

	s := NewBBRV1Sender(clk, rttStats, 1200, nil)

	// First ACK initializes the sampler (no bandwidth sample yet).
	pn1 := protocol.PacketNumber(1)
	// sent_packet_handler passes bytesInFlight *after* adding this packet.
	// Simulate being cwnd-limited so BBR trusts the sample.
	s.OnPacketSent(clk.Now(), s.GetCongestionWindow(), pn1, 1200, true)
	clk.t = clk.t.Add(10 * time.Millisecond)
	s.OnPacketAcked(pn1, 1200, 0, clk.Now())

	// Second ACK should produce a delivery-rate sample.
	pn2 := protocol.PacketNumber(2)
	s.OnPacketSent(clk.Now(), s.GetCongestionWindow(), pn2, 1200, true)
	clk.t = clk.t.Add(100 * time.Millisecond)
	s.OnPacketAcked(pn2, 1200, 0, clk.Now())

	require.NotZero(t, s.btlBw)
	require.NotEqual(t, infBandwidth, s.btlBw)
	require.Greater(t, uint64(s.btlBw), uint64(0))
}

func TestBBRv1SenderIgnoresNonAckElicitingPackets(t *testing.T) {
	clk := &testClock{t: time.Unix(0, 0)}
	rttStats := &utils.RTTStats{}
	rttStats.UpdateRTT(50*time.Millisecond, 0)

	s := NewBBRV1Sender(clk, rttStats, 1200, nil)

	// quic-go uses this flag to mean "ACK-eliciting".
	// Non-ACK-eliciting packets (ACK-only) are never ACKed and not in bytes_in_flight.
	// Ensure we ignore them, otherwise bytesInFlight / sampler state would leak.
	pn := protocol.PacketNumber(1)
	s.OnPacketSent(clk.Now(), 0, pn, 1200, false)

	require.Equal(t, protocol.ByteCount(0), s.bytesInFlight)
	require.Empty(t, s.sentPackets)
}

func TestBBRv1SenderProbeRTTEntryReducesCwnd(t *testing.T) {
	clk := &testClock{t: time.Unix(0, 0)}
	rttStats := &utils.RTTStats{}
	rttStats.UpdateRTT(50*time.Millisecond, 0)

	s := NewBBRV1Sender(clk, rttStats, 1200, nil)
	// Force rtProp to look expired.
	s.rtPropStamp = clk.Now().Add(-2 * bbrv1ProbeRTTInterval)

	// Send and ack one packet to trigger model/state update.
	pn := protocol.PacketNumber(1)
	s.OnPacketSent(clk.Now(), 1200, pn, 1200, true)
	clk.t = clk.t.Add(20 * time.Millisecond)
	s.OnPacketAcked(pn, 1200, 0, clk.Now())

	require.Equal(t, bbrv1ProbeRTT, s.state)
	require.LessOrEqual(t, s.GetCongestionWindow(), s.minPipeCwnd())
}

func TestBBRv1SenderEntersAndExitsRecoveryPacketConservation(t *testing.T) {
	clk := &testClock{t: time.Unix(0, 0)}
	rttStats := &utils.RTTStats{}
	rttStats.UpdateRTT(50*time.Millisecond, 0)

	s := NewBBRV1Sender(clk, rttStats, 1200, nil)

	// Send two packets.
	pn1 := protocol.PacketNumber(1)
	s.OnPacketSent(clk.Now(), 1200, pn1, 1200, true)
	pn2 := protocol.PacketNumber(2)
	s.OnPacketSent(clk.Now(), 2400, pn2, 1200, true)

	// Declare a loss event. This should enter recovery + packet conservation.
	s.OnCongestionEvent(pn1, 1200, 0)
	require.True(t, s.packetConservation)
	require.GreaterOrEqual(t, s.GetCongestionWindow(), s.minPipeCwnd())

	// ACK a new packet beyond the cutback boundary to exit recovery.
	pn3 := protocol.PacketNumber(3)
	s.OnPacketSent(clk.Now(), 2400, pn3, 1200, true)
	clk.t = clk.t.Add(20 * time.Millisecond)
	s.OnPacketAcked(pn3, 1200, 0, clk.Now())
	require.False(t, s.packetConservation)
}
