//go:build quicfecdev

package fecquic

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go/logging"
)

func devPacketLossReasonString(r logging.PacketLossReason) string {
	switch r {
	case logging.PacketLossReorderingThreshold:
		return "reordering_threshold"
	case logging.PacketLossTimeThreshold:
		return "time_threshold"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

func devTimerTypeString(t logging.TimerType) string {
	switch t {
	case logging.TimerTypeACK:
		return "ack"
	case logging.TimerTypePTO:
		return "pto"
	case logging.TimerTypePathProbe:
		return "path_probe"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

type devRetxStats struct {
	mu sync.Mutex

	start time.Time
	// counts by loss reason
	lostByReason map[logging.PacketLossReason]uint64
	lostByEnc    map[logging.EncryptionLevel]uint64
	ptoUpdates   uint64
	ptoExpired   uint64
	ackExpired   uint64
	pathExpired  uint64
}

func init() {
	// Override hook declared in devwrap_default.go.
	devWrapConnTracerHook = devWrapConnTracerImpl
}

func devWrapConnTracerImpl(base *logging.ConnectionTracer) *logging.ConnectionTracer {
	if base == nil {
		return nil
	}
	if os.Getenv("QUIC_FEC_DEV_RETX") != "1" {
		return base
	}
	verbose := os.Getenv("QUIC_FEC_DEV_RETX_VERBOSE") == "1"
	st := &devRetxStats{
		start:        time.Now(),
		lostByReason: make(map[logging.PacketLossReason]uint64),
		lostByEnc:    make(map[logging.EncryptionLevel]uint64),
	}

	dev := &logging.ConnectionTracer{
		UpdatedPTOCount: func(v uint32) {
			st.mu.Lock()
			st.ptoUpdates = uint64(v)
			st.mu.Unlock()
		},
		LostPacket: func(enc logging.EncryptionLevel, pn logging.PacketNumber, reason logging.PacketLossReason) {
			st.mu.Lock()
			st.lostByReason[reason]++
			st.lostByEnc[enc]++
			st.mu.Unlock()
			if verbose {
				fmt.Fprintf(os.Stderr, "[dev-retx] t_ms=%d event=lost enc=%s pn=%d reason=%s\n",
					time.Since(st.start).Milliseconds(), enc, pn, devPacketLossReasonString(reason))
			}
		},
		LossTimerExpired: func(timerType logging.TimerType, enc logging.EncryptionLevel) {
			st.mu.Lock()
			switch timerType {
			case logging.TimerTypePTO:
				st.ptoExpired++
			case logging.TimerTypeACK:
				st.ackExpired++
			case logging.TimerTypePathProbe:
				st.pathExpired++
			}
			st.mu.Unlock()
			if verbose {
				fmt.Fprintf(os.Stderr, "[dev-retx] t_ms=%d event=timer_expired type=%s enc=%s\n",
					time.Since(st.start).Milliseconds(), devTimerTypeString(timerType), enc)
			}
		},
		Close: func() {
			st.mu.Lock()
			defer st.mu.Unlock()
			fmt.Fprintf(os.Stderr, "[dev-retx-summary] pto_updates=%d pto_expired=%d ack_expired=%d path_expired=%d\n",
				st.ptoUpdates, st.ptoExpired, st.ackExpired, st.pathExpired)
			for r, c := range st.lostByReason {
				fmt.Fprintf(os.Stderr, "[dev-retx-summary] lost_reason=%s count=%d\n", devPacketLossReasonString(r), c)
			}
			for e, c := range st.lostByEnc {
				fmt.Fprintf(os.Stderr, "[dev-retx-summary] lost_enc=%s count=%d\n", e, c)
			}
		},
	}
	return logging.NewMultiplexedConnectionTracer(base, dev)
}
