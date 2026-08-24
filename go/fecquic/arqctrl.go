package fecquic

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/quic-go/quic-go/internal/fecwire"
)

const (
	arqMsgACK  uint8 = fecwire.TypeACK
	arqMsgNACK uint8 = fecwire.TypeNACK
	arqMsgDONE uint8 = fecwire.TypeDONE // receiver completed file (EOF-like signal)
)

type AckSuccess struct {
	BlockID uint32
}

type NackNeedMore struct {
	BlockID    uint32
	AttemptIdx uint16
	RecvCount  uint16
}

// DoneFile indicates the receiver has delivered the full file.
// This is sent on the reliable control uni-stream from server->client.
type DoneFile struct {
	FileID  uint32
	Written uint64 // bytes delivered (best-effort, for diagnostics)
	Ok      uint8  // 1=success, 0=failure
}

func writeDone(w io.Writer, d DoneFile) error {
	if _, err := w.Write([]byte{arqMsgDONE}); err != nil {
		return err
	}
	var b [13]byte
	binary.LittleEndian.PutUint32(b[0:4], d.FileID)
	binary.LittleEndian.PutUint64(b[4:12], d.Written)
	b[12] = d.Ok
	_, err := w.Write(b[:])
	return err
}

func writeAck(w io.Writer, a AckSuccess) error {
	if _, err := w.Write([]byte{arqMsgACK}); err != nil {
		return err
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[0:4], a.BlockID)
	_, err := w.Write(b[:])
	return err
}

func writeNack(w io.Writer, n NackNeedMore) error {
	if _, err := w.Write([]byte{arqMsgNACK}); err != nil {
		return err
	}
	var b [8]byte
	binary.LittleEndian.PutUint32(b[0:4], n.BlockID)
	binary.LittleEndian.PutUint16(b[4:6], n.AttemptIdx)
	binary.LittleEndian.PutUint16(b[6:8], n.RecvCount)
	_, err := w.Write(b[:])
	return err
}

// Read one control message from r and return type and value.
func readCtrl(r io.Reader) (uint8, interface{}, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return 0, nil, err
	}
	switch t[0] {
	case arqMsgACK:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		a := AckSuccess{
			BlockID: binary.LittleEndian.Uint32(b[0:4]),
		}
		return t[0], a, nil
	case arqMsgNACK:
		var b [8]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n := NackNeedMore{
			BlockID:    binary.LittleEndian.Uint32(b[0:4]),
			AttemptIdx: binary.LittleEndian.Uint16(b[4:6]),
			RecvCount:  binary.LittleEndian.Uint16(b[6:8]),
		}
		return t[0], n, nil
	case arqMsgDONE:
		var b [13]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		d := DoneFile{
			FileID:  binary.LittleEndian.Uint32(b[0:4]),
			Written: binary.LittleEndian.Uint64(b[4:12]),
			Ok:      b[12],
		}
		return t[0], d, nil
	default:
		return 0, nil, fmt.Errorf("unknown ctrl type %d", t[0])
	}
}
