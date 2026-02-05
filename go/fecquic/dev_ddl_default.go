package fecquic

// devLogRxDDL is a develop-only hook for tracing receiver deadline behavior.
// In normal builds it is a no-op.

var devLogRxDDLHook = func(_ string, _ ...any) {}

func devLogRxDDL(msg string, args ...any) {
	devLogRxDDLHook(msg, args...)
}
