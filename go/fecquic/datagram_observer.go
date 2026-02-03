package fecquic

import (
	"sync/atomic"

	"github.com/quic-go/quic-go/internal/fecwire"
)

type dgramEvtType uint8

const (
	dgramEvtAck  dgramEvtType = 1
	dgramEvtLost dgramEvtType = 2
)

type dgramEvt struct {
	typ     dgramEvtType
	blockID uint16
	symID   uint8
	k       uint8
}

// datagramObserver emits per-DATAGRAM ack / loss events based on QUIC packet loss detection.
// It parses the FEC header in the datagram payload and forwards only small metadata to avoid
// retaining large byte slices.
//
// This is used to implement sender-side repair scheduling without receiver-side NACK.
type datagramObserver struct {
	ch      chan<- dgramEvt
	dropped atomic.Int64
}

func (o *datagramObserver) OnDatagramAcked(data []byte) {
	o.emit(dgramEvtAck, data)
}

func (o *datagramObserver) OnDatagramLost(data []byte) {
	o.emit(dgramEvtLost, data)
}

func (o *datagramObserver) emit(typ dgramEvtType, data []byte) {
	if o == nil || o.ch == nil {
		return
	}
	var fh fecwire.FECHeader
	if !fh.UnmarshalBinary(data) {
		return
	}
	if fh.Scheme != fecwire.SchemeRaptorQ {
		return
	}
	e := dgramEvt{typ: typ, blockID: fh.BlockID, symID: fh.SymID, k: fh.K}
	select {
	case o.ch <- e:
	default:
		// Never block the QUIC loss / ACK processing path.
		o.dropped.Add(1)
	}
}

func (o *datagramObserver) Dropped() int64 {
	if o == nil {
		return 0
	}
	return o.dropped.Load()
}
