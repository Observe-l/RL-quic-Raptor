package congestion

import (
	"time"

	"github.com/quic-go/quic-go/internal/protocol"
)

// NoopSender is a lab-only congestion controller that bypasses congestion control.
// It always allows sending and never reduces the congestion window.
// WARNING: Use only for isolated lab microbenchmarks (e.g., FEC constant-rate tests).
type NoopSender struct{}

var _ SendAlgorithmWithDebugInfos = (*NoopSender)(nil)

func NewNoopSender() *NoopSender { return &NoopSender{} }

func (n *NoopSender) TimeUntilSend(bytesInFlight protocol.ByteCount) time.Time { return time.Now() }
func (n *NoopSender) HasPacingBudget(now time.Time) bool                       { return true }
func (n *NoopSender) OnPacketSent(sentTime time.Time, bytesInFlight protocol.ByteCount, packetNumber protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
}
func (n *NoopSender) CanSend(bytesInFlight protocol.ByteCount) bool { return true }
func (n *NoopSender) MaybeExitSlowStart()                           {}
func (n *NoopSender) OnPacketAcked(number protocol.PacketNumber, ackedBytes protocol.ByteCount, priorInFlight protocol.ByteCount, eventTime time.Time) {
}
func (n *NoopSender) OnCongestionEvent(number protocol.PacketNumber, lostBytes protocol.ByteCount, priorInFlight protocol.ByteCount) {
}
func (n *NoopSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}
func (n *NoopSender) SetMaxDatagramSize(protocol.ByteCount)             {}

// Debug/info
func (n *NoopSender) InSlowStart() bool                       { return false }
func (n *NoopSender) InRecovery() bool                        { return false }
func (n *NoopSender) GetCongestionWindow() protocol.ByteCount { return 1 << 62 }
