//go:build quicfecdev

package fecquic

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

var devARQT0 atomic.Int64

func devARQNowMs() int64 {
	t0 := devARQT0.Load()
	now := time.Now().UnixNano()
	if t0 == 0 {
		if devARQT0.CompareAndSwap(0, now) {
			t0 = now
		} else {
			t0 = devARQT0.Load()
		}
	}
	return (now - t0) / 1e6
}

func init() {
	// Override hooks declared in arq_devhooks_default.go.
	devARQOnClientNackHook = func(n NackNeedMore, deficit int, rstep int, cand int, k int, nextESI int, repairsOut int) {
		fmt.Fprintf(os.Stderr, "[dev-arq] t_ms=%d event=nack block=%d attempt=%d recv_count=%d k=%d deficit=%d rstep=%d append=%d next_esi=%d repairs_out=%d\n",
			devARQNowMs(), n.BlockID, n.AttemptIdx, n.RecvCount, k, deficit, rstep, cand, nextESI, repairsOut)
	}

	devARQOnClientRepairSentHook = func(blockID uint32, esi int) {
		if os.Getenv("QUIC_FEC_DEV_ARQ_REPAIR_SENT") != "1" {
			return
		}
		fmt.Fprintf(os.Stderr, "[dev-arq] t_ms=%d event=repair_sent block=%d esi=%d\n", devARQNowMs(), blockID, esi)
	}

	devARQOnClientAckHook = func(a AckSuccess) {
		fmt.Fprintf(os.Stderr, "[dev-arq] t_ms=%d event=ack block=%d\n",
			devARQNowMs(), a.BlockID)
	}
}
