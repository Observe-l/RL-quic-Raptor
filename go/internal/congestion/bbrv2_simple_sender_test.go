package congestion

import (
	"math"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestSimpleBBRv2ExposesFiniteStartupPacingRate(t *testing.T) {
	const packetSize protocol.ByteCount = 1200
	rttStats := &utils.RTTStats{}
	sender := NewSimpleBBRv2Sender(
		bbrv2TestClock{now: time.Unix(100, 0)},
		rttStats,
		packetSize,
		nil,
	)

	rate := sender.PacingRateBps()
	require.Positive(t, rate)
	require.NotEqual(t, uint64(math.MaxUint64), rate)
	require.Equal(t, uint64(sender.pacingRateForDeadline()), rate)
	require.True(t, sender.InSlowStart())
}
