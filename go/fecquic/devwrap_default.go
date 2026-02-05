package fecquic

import "github.com/quic-go/quic-go/logging"

// devWrapConnTracer is a build-tag controlled hook used by the quicfec develop tools.
// In normal builds it is a no-op.

var devWrapConnTracerHook = func(t *logging.ConnectionTracer) *logging.ConnectionTracer { return t }

func devWrapConnTracer(t *logging.ConnectionTracer) *logging.ConnectionTracer {
	return devWrapConnTracerHook(t)
}
