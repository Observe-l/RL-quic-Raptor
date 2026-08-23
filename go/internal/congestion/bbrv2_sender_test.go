package congestion

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

type bbrv2TestClock struct {
	now time.Time
}

func TestBBRv2UsesQUICInitialRTT(t *testing.T) {
	const packetSize protocol.ByteCount = 1200
	const initialRTT = 25 * time.Millisecond

	rttStats := &utils.RTTStats{}
	rttStats.SetInitialRTT(initialRTT)
	sender := NewBBRv2Sender(
		bbrv2TestClock{now: time.Unix(100, 0)},
		rttStats,
		packetSize,
		nil,
	)

	require.Equal(t, initialRTT, sender.MinRtt())
	require.Equal(
		t,
		BandwidthFromBytesAndTimeDelta(ByteCount(initialCongestionWindow)*packetSize, initialRTT).Mul(2.885),
		sender.PacingRate(),
	)
}

func TestBBRv2ReceivesECNCEEvent(t *testing.T) {
	const packetSize protocol.ByteCount = 1200
	now := time.Unix(100, 0)
	sender := newBBR2Sender(bbrv2TestClock{now: now}, packetSize, 10*packetSize, false)

	sender.OnCongestionEventEx(0, now, nil, nil, 1)

	require.EqualValues(t, 1, sender.model.ecnCEInRound)
}

func (c bbrv2TestClock) Now() time.Time { return c.now }

func TestBBRv2BatchEventProducesBandwidthAndPacingRate(t *testing.T) {
	const packetSize protocol.ByteCount = 1200
	now := time.Unix(100, 0)
	sender := newBBR2Sender(bbrv2TestClock{now: now}, packetSize, 32*packetSize, false)

	initialPacing := sender.PacingRate()
	require.Positive(t, uint64(initialPacing))

	for i := protocol.PacketNumber(0); i < 20; i++ {
		sentAt := now.Add(time.Duration(i) * time.Millisecond)
		sender.OnPacketSent(sentAt, protocol.ByteCount(i)*packetSize, i, packetSize, true)
	}

	acked := make([]AckedPacketInfo, 0, 20)
	for i := protocol.PacketNumber(0); i < 20; i++ {
		acked = append(acked, AckedPacketInfo{
			PacketNumber: i,
			BytesAcked:   packetSize,
			SentTime:     now.Add(time.Duration(i) * time.Millisecond),
		})
	}
	sender.OnCongestionEventEx(20*packetSize, now.Add(200*time.Millisecond), acked, nil, 0)

	require.Positive(t, uint64(sender.BandwidthEstimate()))
	require.Positive(t, uint64(sender.PacingRate()))
	require.Equal(t, uint64(sender.PacingRate()), sender.PacingRateBps())
	require.NotZero(t, sender.model.MinRtt())

	for i := protocol.PacketNumber(20); i < 30; i++ {
		sentAt := now.Add(250 * time.Millisecond).Add(time.Duration(i-20) * time.Millisecond)
		sender.OnPacketSent(sentAt, protocol.ByteCount(i-20)*packetSize, i, packetSize, true)
	}
	lost := []LostPacketInfo{{PacketNumber: 20, BytesLost: packetSize}}
	acked = []AckedPacketInfo{{
		PacketNumber: 21,
		BytesAcked:   packetSize,
		SentTime:     now.Add(251 * time.Millisecond),
	}}
	sender.OnCongestionEventEx(10*packetSize, now.Add(450*time.Millisecond), acked, lost, 0)

	require.Equal(t, ByteCount(packetSize), sender.model.TotalBytesLost())
	require.Positive(t, uint64(sender.PacingRate()))
	require.Equal(t, uint64(sender.PacingRate()), sender.PacingRateBps())
}
