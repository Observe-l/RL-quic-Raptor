package fecquic

import (
	"fmt"
	"sync/atomic"

	"github.com/quic-go/quic-go/logging"
)

type quicConnStats struct {
	sentLongPkts      atomic.Uint64
	sentLongBytes     atomic.Uint64
	sentShortPkts     atomic.Uint64
	sentShortBytes    atomic.Uint64
	acked1RTTPkts     atomic.Uint64
	lost1RTTPkts      atomic.Uint64
	lostHandshakePkts atomic.Uint64
	lostInitialPkts   atomic.Uint64
}

func newQuicConnStats() *quicConnStats { return &quicConnStats{} }

func newQuicConnStatsTracer(s *quicConnStats) *logging.ConnectionTracer {
	if s == nil {
		return nil
	}
	return &logging.ConnectionTracer{
		SentLongHeaderPacket: func(_ *logging.ExtendedHeader, size logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			s.sentLongPkts.Add(1)
			s.sentLongBytes.Add(uint64(size))
		},
		SentShortHeaderPacket: func(_ *logging.ShortHeader, size logging.ByteCount, _ logging.ECN, _ *logging.AckFrame, _ []logging.Frame) {
			s.sentShortPkts.Add(1)
			s.sentShortBytes.Add(uint64(size))
		},
		AcknowledgedPacket: func(enc logging.EncryptionLevel, _ logging.PacketNumber) {
			if enc == logging.Encryption1RTT {
				s.acked1RTTPkts.Add(1)
			}
		},
		LostPacket: func(enc logging.EncryptionLevel, _ logging.PacketNumber, _ logging.PacketLossReason) {
			switch enc {
			case logging.Encryption1RTT:
				s.lost1RTTPkts.Add(1)
			case logging.EncryptionHandshake:
				s.lostHandshakePkts.Add(1)
			case logging.EncryptionInitial:
				s.lostInitialPkts.Add(1)
			}
		},
	}
}

func (s *quicConnStats) Format(prefix string) string {
	sentLongPkts := s.sentLongPkts.Load()
	sentLongBytes := s.sentLongBytes.Load()
	sentShortPkts := s.sentShortPkts.Load()
	sentShortBytes := s.sentShortBytes.Load()
	acked1RTT := s.acked1RTTPkts.Load()
	lost1RTT := s.lost1RTTPkts.Load()
	lostHS := s.lostHandshakePkts.Load()
	lostInit := s.lostInitialPkts.Load()

	sentPkts := sentLongPkts + sentShortPkts
	sentBytes := sentLongBytes + sentShortBytes

	return fmt.Sprintf("%s sent_pkts=%d sent_bytes=%d sent_long_pkts=%d sent_long_bytes=%d sent_short_pkts=%d sent_short_bytes=%d acked_1rtt_pkts=%d lost_1rtt_pkts=%d lost_handshake_pkts=%d lost_initial_pkts=%d",
		prefix,
		sentPkts, sentBytes,
		sentLongPkts, sentLongBytes,
		sentShortPkts, sentShortBytes,
		acked1RTT, lost1RTT, lostHS, lostInit,
	)
}
