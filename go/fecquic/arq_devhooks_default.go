package fecquic

// Develop-only ARQ debug hooks.
//
// These wrappers are always compiled so gopls can type-check this package
// regardless of build tags. In non-dev builds they are no-ops.

var devARQOnClientNackHook = func(_ NackNeedMore, _ int, _ int, _ int, _ int, _ int) {}
var devARQOnClientRepairSentHook = func(_ uint16, _ int) {}
var devARQOnClientAckHook = func(_ AckSuccess) {}

func devARQOnClientNack(n NackNeedMore, deficit int, cand int, k int, nextESI int, repairsOut int) {
	devARQOnClientNackHook(n, deficit, cand, k, nextESI, repairsOut)
}

func devARQOnClientRepairSent(blockID uint16, esi int) {
	devARQOnClientRepairSentHook(blockID, esi)
}

func devARQOnClientAck(a AckSuccess) {
	devARQOnClientAckHook(a)
}
