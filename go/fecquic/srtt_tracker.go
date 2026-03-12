package fecquic

import (
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go/logging"
)

// serverSRTTNanos tracks the most recently observed QUIC smoothed RTT on the server side.
// It is updated via QUIC tracing (UpdatedMetrics callback).
//
// Note: The experiment harness runs one active connection at a time, so a single global
// value is sufficient. If you later serve multiple concurrent connections, prefer tracking
// SRTT per-connection.
var serverSRTTNanos atomic.Int64

func configuredServerRTT() time.Duration {
	if v := os.Getenv("QUIC_FEC_SERVER_RTT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 0
}

func effectiveServerRTT() time.Duration {
	if rtt := configuredServerRTT(); rtt > 0 {
		return rtt
	}
	if srtt := latestServerSRTT(); srtt > 0 {
		return srtt
	}
	if v := os.Getenv("RTT_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return 0
}

func latestServerSRTT() time.Duration {
	ns := serverSRTTNanos.Load()
	if ns <= 0 {
		return 0
	}
	return time.Duration(ns)
}

func newServerSRTTTracer() *logging.ConnectionTracer {
	return &logging.ConnectionTracer{
		UpdatedMetrics: func(rttStats *logging.RTTStats, _, _ logging.ByteCount, _ int) {
			if rttStats == nil {
				return
			}
			srtt := rttStats.SmoothedRTT()
			if srtt <= 0 {
				return
			}
			serverSRTTNanos.Store(srtt.Nanoseconds())
		},
	}
}
