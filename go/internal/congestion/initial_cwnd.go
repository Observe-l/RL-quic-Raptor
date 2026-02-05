package congestion

import (
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/quic-go/quic-go/internal/protocol"
)

var (
	initialCWNDOnce     sync.Once
	initialCWNDPacketsV protocol.ByteCount = protocol.ByteCount(initialCongestionWindow)
)

// initialCwndPackets returns the initial congestion window in packets.
//
// It can be overridden for lab experiments via QUIC_GO_INITIAL_CWND_PKTS.
// Invalid / empty values are ignored.
func initialCwndPackets() protocol.ByteCount {
	initialCWNDOnce.Do(func() {
		raw := strings.TrimSpace(os.Getenv("QUIC_GO_INITIAL_CWND_PKTS"))
		if raw == "" {
			return
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return
		}
		if n < minCongestionWindowPackets {
			n = minCongestionWindowPackets
		}
		// Keep an upper bound to avoid surprising memory / pacing artifacts.
		if n > 10000 {
			n = 10000
		}
		initialCWNDPacketsV = protocol.ByteCount(n)
	})
	return initialCWNDPacketsV
}
