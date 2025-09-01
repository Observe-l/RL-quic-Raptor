package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/fec"
	"github.com/quic-go/quic-go/internal/dropper"
	"github.com/quic-go/quic-go/internal/fecwire"
)

func main() {
	var (
		addr       = flag.String("addr", "localhost:4242", "server addr")
		file       = flag.String("file", "test_data/train_FD001.txt", "input file")
		scheme     = flag.String("scheme", "polar", "fec scheme: rlc|rs|polar|raptorq")
		N          = flag.Int("N", 8, "block length")
		K          = flag.Int("K", 6, "information symbols")
		L          = flag.Int("L", 1100, "symbol bytes")
		lossP      = flag.Float64("loss", 0.005, "sender drop probability")
		seed       = flag.Int64("seed", 1, "rng seed")
		postWait   = flag.Duration("post-wait", 2*time.Millisecond, "max time to wait for server completion ack after sending")
		warnDgram  = flag.Int("dgram-warn", 1200, "warn if datagram bytes exceed this (0=disable)")
		paceEach   = flag.Duration("pace", 300*time.Microsecond, "sleep between DATAGRAM sends to avoid receiver queue overflow (0=disable)")
		blockPause = flag.Duration("block-pause", 2*time.Millisecond, "sleep after each block (0=disable)")
		// Polar selection flags
		polarMode       = flag.String("polar-mode", "3gpp", "polar params: 3gpp|artifacts|runtime")
		polar3gppTable  = flag.String("polar-3gpp-table", "docs/polar_table_5_3_1_2_1_inverted.txt", "3GPP table path (index, rank; larger=more reliable)")
		polarArtifacts  = flag.String("polar-artifacts", "tables", "base dir of polar artifacts (per N,K,e)")
		polarArtifactsE = flag.Int("polar-art-e", 60, "artifacts epsilon bucket (e)")
		polarEps        = flag.Float64("polar-eps", 0.01, "runtime epsilon for BEC selection")
	)
	flag.Parse()

	ctx := context.Background()
	tlsConf := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"quic-fec-demo"}}
	qconf := &quic.Config{EnableDatagrams: true}
	conn, err := quic.DialAddr(ctx, *addr, tlsConf, qconf)
	if err != nil {
		fmt.Println("dial:", err)
		return
	}
	// Don't close immediately after sending; wait for server ack / finalize to avoid
	// truncating in-flight DATAGRAMs. We'll close explicitly at the end.

	f, err := os.Open(*file)
	if err != nil {
		fmt.Println("open file:", err)
		return
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		fmt.Println("read file:", err)
		return
	}

	rng := rand.New(rand.NewSource(*seed))
	drop := dropper.New(*lossP, rng)

	// send metadata on a reliable stream first
	type meta struct {
		Name   string `json:"name"`
		Size   int    `json:"size"`
		Scheme string `json:"scheme"`
		N      int    `json:"N"`
		K      int    `json:"K"`
		L      int    `json:"L"`
		SHA256 string `json:"sha256,omitempty"`
		// For Polar, we don't send params; both sides must use matching flags.
		// These are included for logging/visibility only.
		PolarMode       string  `json:"polar_mode,omitempty"`
		Polar3GPPTable  string  `json:"polar_3gpp_table,omitempty"`
		PolarArtifacts  string  `json:"polar_artifacts,omitempty"`
		PolarArtifactsE int     `json:"polar_artifacts_e,omitempty"`
		PolarEps        float64 `json:"polar_eps,omitempty"`
	}
	// compute SHA-256 for integrity
	sum := sha256.Sum256(data)
	m := meta{
		Name:            filepath.Base(*file),
		Size:            len(data),
		Scheme:          *scheme,
		N:               *N,
		K:               *K,
		L:               *L,
		SHA256:          hex.EncodeToString(sum[:]),
		PolarMode:       *polarMode,
		Polar3GPPTable:  *polar3gppTable,
		PolarArtifacts:  *polarArtifacts,
		PolarArtifactsE: *polarArtifactsE,
		PolarEps:        *polarEps,
	}
	// Open a bidirectional stream for metadata and completion ack
	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		fmt.Println("open stream:", err)
		return
	}
	enc := json.NewEncoder(str)
	if err := enc.Encode(&m); err != nil {
		fmt.Println("write meta:", err)
		return
	}
	// Half-close write side for meta; keep stream open for server ack
	// Half-close write side for meta; keep stream open for server ack
	if err := str.Close(); err != nil {
		fmt.Println("close meta stream:", err)
		return
	}

	total := len(data)
	block := 0
	for off := 0; off < total; {
		// slice next K*L bytes (pad zeros)
		blockSize := (*K) * (*L)
		buf := make([]byte, blockSize)
		copied := copy(buf, data[off:])
		_ = copied
		// split into K symbols for non-raptorq schemes
		src := make([][]byte, *K)
		for i := 0; i < *K; i++ {
			src[i] = buf[i*(*L) : (i+1)*(*L)]
		}
		R := *N - *K
		var par []fec.Packet
		switch *scheme {
		case "rlc":
			par = fec.EncodeRLC(src, *K, R, "gf256")
		case "rs":
			var err error
			par, err = fec.EncodeRS(src, *K, R)
			if err != nil {
				fmt.Println("rs:", err)
				return
			}
		case "raptorq":
			// High-level encode for simplicity and correctness
			pkts, err := fec.RaptorQEncodeBlock(data[off:min(off+blockSize, total)], *N, *K, *L)
			if err != nil {
				fmt.Println("raptorq enc:", err)
				return
			}
			// Interleave data and repair to spread parity early and uniformly.
			di, pj := 0, 0 // data index [0..K-1], parity index [0..R-1] mapped to symID K+pj
			R := *N - *K
			for t := 0; t < *N; t++ {
				iterStart := time.Now()
				sendParity := false
				if di >= *K {
					sendParity = true
				} else if pj >= R {
					sendParity = false
				} else {
					// roughly 1:1 interleave with slight bias to deliver some repair early
					sendParity = pj <= di-1
				}
				if !drop.Drop() {
					var symID int
					if sendParity {
						symID = *K + pj
						pj++
					} else {
						symID = di
						di++
					}
					payload := pkts[symID].Data
					hdr := fecwire.FECHeader{Version: 1, Scheme: schemeID(*scheme), BlockID: uint16(block), N: uint8(*N), K: uint8(*K), SymID: uint8(symID), PayloadLen: uint32(len(payload))}
					b := hdr.MarshalBinary(nil)
					dgram := append(b, payload...)
					if *warnDgram > 0 && len(dgram) > *warnDgram {
						fmt.Printf("warn: datagram size %d exceeds warn threshold %d; consider reducing -L (symbol bytes)\n", len(dgram), *warnDgram)
						*warnDgram = 0
					}
					if err := conn.SendDatagram(dgram); err != nil {
						fmt.Println("send:", err)
						return
					}
				}
				if *paceEach > 0 {
					if slept := time.Since(iterStart); slept < *paceEach {
						time.Sleep(*paceEach - slept)
					}
				}
			}
			if *blockPause > 0 {
				time.Sleep(*blockPause)
			}
			block++
			off += blockSize
			continue
		default: // polar
			var pp *fec.PacketPolarParams
			var err error
			switch *polarMode {
			case "3gpp":
				pp, err = fec.NewPacketPolarParamsFrom3GPP(*polar3gppTable, *N, *K, *L)
			case "artifacts":
				pp, err = fec.NewPacketPolarParamsFromArtifacts(*polarArtifacts, *N, *K, *polarArtifactsE, *L)
			case "runtime":
				pp, err = fec.NewPacketPolarParams(*N, *K, *polarEps, *L)
			default:
				fmt.Println("unknown polar-mode:", *polarMode)
				return
			}
			if err != nil {
				fmt.Println("polar params:", err)
				return
			}
			parData := fec.PacketPolarEncode(pp, src)
			par = make([]fec.Packet, R)
			for j := 0; j < R; j++ {
				par[j] = fec.Packet{Index: *K + j, Data: parData[j]}
			}
		}
		// send data and parity interleaved to get parity flowing earlier (non-RaptorQ)
		di, pj := 0, 0
		for t := 0; t < *N; t++ {
			iterStart := time.Now()
			// choose next: prefer keeping counts balanced so parity starts early
			sendParity := false
			if di >= *K {
				sendParity = true
			} else if pj >= R {
				sendParity = false
			} else {
				// interleave roughly 1:1
				sendParity = pj <= di-1
			}
			if !drop.Drop() {
				var payload []byte
				var symID uint8
				if sendParity {
					payload = par[pj].Data
					symID = uint8(*K + pj)
					pj++
				} else {
					payload = src[di]
					symID = uint8(di)
					di++
				}
				hdr := fecwire.FECHeader{Version: 1, Scheme: schemeID(*scheme), BlockID: uint16(block), N: uint8(*N), K: uint8(*K), SymID: symID, PayloadLen: uint32(len(payload))}
				b := hdr.MarshalBinary(nil)
				dgram := append(b, payload...)
				if *warnDgram > 0 && len(dgram) > *warnDgram {
					fmt.Printf("warn: datagram size %d exceeds warn threshold %d; consider reducing -L (symbol bytes)\n", len(dgram), *warnDgram)
					*warnDgram = 0
				}
				if err := conn.SendDatagram(dgram); err != nil {
					fmt.Println("send:", err)
					return
				}
			}
			if *paceEach > 0 {
				if slept := time.Since(iterStart); slept < *paceEach {
					time.Sleep(*paceEach - slept)
				}
			}
		}
		if *blockPause > 0 {
			time.Sleep(*blockPause)
		}
		block++
		off += blockSize
	}
	// Wait for server completion ack on an incoming stream.
	// Compute a generous deadline as a function of pacing, number of blocks,
	// and a fixed cushion to cover scheduling and decode time.
	minWait := *postWait
	blocks := (total + (*K)*(*L) - 1) / ((*K) * (*L))
	if *paceEach > 0 {
		totalDgrams := blocks * (*N)
		drain := time.Duration(totalDgrams) * (*paceEach)
		if *blockPause > 0 {
			drain += time.Duration(blocks) * (*blockPause)
		}
		// Scale up the drain by a larger factor to account for netem and queuing,
		// and add a fixed cushion.
		drain = drain*8 + 200*time.Millisecond
		if drain > minWait {
			minWait = drain
		}
	} else if minWait <= 0 {
		minWait = 500 * time.Millisecond
	}
	// Also add a size-based cushion: ~2ms per block, capped at 6s.
	sizeCushion := time.Duration(blocks) * 2 * time.Millisecond
	if sizeCushion > 6*time.Second {
		sizeCushion = 6 * time.Second
	}
	// Ensure a minimum overall wait for large objects to prevent premature close.
	if blocks > 600 && minWait < 20*time.Second {
		minWait = 20 * time.Second
	} else if blocks > 300 && minWait < 10*time.Second {
		minWait = 10 * time.Second
	} else if blocks > 100 && minWait < 5*time.Second {
		minWait = 5 * time.Second
	}
	ackDeadline := time.Now().Add(minWait + sizeCushion)
	for time.Now().Before(ackDeadline) {
		perTry := 200 * time.Millisecond
		if remain := time.Until(ackDeadline); remain < perTry {
			perTry = remain
		}
		ackCtx, cancel := context.WithTimeout(ctx, perTry)
		srvStr, err := conn.AcceptStream(ackCtx)
		cancel()
		if err != nil {
			// retry until deadline
			continue
		}
		// Read and discard small ack payload
		buf := make([]byte, 1)
		_, _ = io.ReadFull(srvStr, buf)
		_ = srvStr.Close()
		break
	}
	// No additional linger needed; the extended ack wait above should suffice.
	_ = conn.CloseWithError(0, "bye")
}

func schemeID(s string) uint8 {
	switch s {
	case "rlc":
		return fecwire.SchemeRLC
	case "rs":
		return fecwire.SchemeRS
	case "raptorq":
		return fecwire.SchemeRaptorQ
	default:
		return fecwire.SchemePolar
	}
}
