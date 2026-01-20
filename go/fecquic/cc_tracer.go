package fecquic

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go/logging"
)

// NewCCDebugConnTracer emits a sender-side bandwidth estimate to stderr.
//
// The estimate is computed from transport-observable signals:
//   bw ~= cwnd / srtt
// For BBRv2 we divide cwnd by the cwnd gain (~2) to approximate BDP bandwidth.
//
// Output format (one line):
//   [cc-estimate] {"algo":"bbrv2","method":"cwnd_srtt","bw_mbps":...,"srtt_ms":...,"cwnd_bytes":...}
func NewCCDebugConnTracer() *logging.ConnectionTracer {
	algo := os.Getenv("QUIC_FEC_CC_ALGO")
	bypass := os.Getenv("QUIC_FEC_CC_BYPASS")
	// throttle + state
	var mu sync.Mutex
	var last time.Time
	var lastBw float64

	return &logging.ConnectionTracer{
		UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, _ logging.ByteCount, _ int) {
			// Only emit when CC is enabled.
			if bypass == "1" {
				return
			}
			if rttStats == nil {
				return
			}
			srtt := rttStats.SmoothedRTT()
			if srtt <= 0 {
				return
			}
			cwndBytes := float64(cwnd)
			// Approximate BDP for BBRv2-like senders (cwnd gain ~2).
			scaled := cwndBytes
			if algo == "bbr" || algo == "bbrv2" {
				scaled = cwndBytes / 2.0
			}
			bwMbps := (scaled * 8.0 / 1e6) / (float64(srtt) / float64(time.Second))
			if !(bwMbps > 0) {
				return
			}

			now := time.Now()
			mu.Lock()
			defer mu.Unlock()
			if !last.IsZero() && now.Sub(last) < 200*time.Millisecond {
				return
			}
			// Avoid emitting the same value repeatedly.
			if lastBw != 0 && bwMbps == lastBw {
				return
			}
			last = now
			lastBw = bwMbps
			fmt.Fprintf(os.Stderr, "[cc-estimate] {\"algo\":%q,\"method\":\"cwnd_srtt\",\"bw_mbps\":%.6f,\"srtt_ms\":%.3f,\"cwnd_bytes\":%.0f}\n", algo, bwMbps, float64(srtt.Microseconds())/1000.0, cwndBytes)
		},
	}
}
