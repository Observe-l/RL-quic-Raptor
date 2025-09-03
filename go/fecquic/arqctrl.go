package fecquic

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	arqMsgACK  uint8 = 1
	arqMsgNACK uint8 = 2
	arqMsgPROG uint8 = 3
)

type AckSuccess struct {
	FileID          uint32
	ClusterID       uint32
	AttemptIdx      uint16
	RxUnique        uint16
	UsedRepairs     uint16
	DecodeLatencyMs uint32
}

type NackNeedMore struct {
	FileID         uint32
	ClusterID      uint32
	AttemptIdx     uint16
	RxUnique       uint16
	RecommendExtra uint16
	Reason         uint8 // 0=DDL,1=CAP,2=OTHER
}

func writeAck(w io.Writer, a AckSuccess) error {
	if _, err := w.Write([]byte{arqMsgACK}); err != nil {
		return err
	}
	var b [16]byte
	binary.LittleEndian.PutUint32(b[0:4], a.FileID)
	binary.LittleEndian.PutUint32(b[4:8], a.ClusterID)
	binary.LittleEndian.PutUint16(b[8:10], a.AttemptIdx)
	binary.LittleEndian.PutUint16(b[10:12], a.RxUnique)
	binary.LittleEndian.PutUint16(b[12:14], a.UsedRepairs)
	if _, err := w.Write(b[:14]); err != nil {
		return err
	}
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], a.DecodeLatencyMs)
	_, err := w.Write(c[:])
	return err
}

func writeNack(w io.Writer, n NackNeedMore) error {
	if _, err := w.Write([]byte{arqMsgNACK}); err != nil {
		return err
	}
	var b [13]byte
	binary.LittleEndian.PutUint32(b[0:4], n.FileID)
	binary.LittleEndian.PutUint32(b[4:8], n.ClusterID)
	binary.LittleEndian.PutUint16(b[8:10], n.AttemptIdx)
	binary.LittleEndian.PutUint16(b[10:12], n.RxUnique)
	if _, err := w.Write(b[:12]); err != nil {
		return err
	}
	var c [3]byte
	binary.LittleEndian.PutUint16(c[0:2], n.RecommendExtra)
	c[2] = n.Reason
	_, err := w.Write(c[:])
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
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		a := AckSuccess{
			FileID:          binary.LittleEndian.Uint32(b[0:4]),
			ClusterID:       binary.LittleEndian.Uint32(b[4:8]),
			AttemptIdx:      binary.LittleEndian.Uint16(b[8:10]),
			RxUnique:        binary.LittleEndian.Uint16(b[10:12]),
			UsedRepairs:     binary.LittleEndian.Uint16(b[12:14]),
			DecodeLatencyMs: binary.LittleEndian.Uint32(b[14:18]),
		}
		return t[0], a, nil
	case arqMsgNACK:
		var b [15]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, nil, err
		}
		n := NackNeedMore{
			FileID:         binary.LittleEndian.Uint32(b[0:4]),
			ClusterID:      binary.LittleEndian.Uint32(b[4:8]),
			AttemptIdx:     binary.LittleEndian.Uint16(b[8:10]),
			RxUnique:       binary.LittleEndian.Uint16(b[10:12]),
			RecommendExtra: binary.LittleEndian.Uint16(b[12:14]),
			Reason:         b[14],
		}
		return t[0], n, nil
	default:
		return 0, nil, fmt.Errorf("unknown ctrl type %d", t[0])
	}
}
