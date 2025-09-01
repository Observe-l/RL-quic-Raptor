package main

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"io"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/fec"
	"github.com/quic-go/quic-go/internal/fecwire"
)

type meta struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	Scheme string `json:"scheme"`
	N      int    `json:"N"`
	K      int    `json:"K"`
	L      int    `json:"L"`
	SHA256 string `json:"sha256,omitempty"`
}

type blockBuffer struct {
	recv   map[int]fec.Packet
	offset int // file offset for this block (bytes)
	size   int // expected bytes to write for this block (<= K*L)
	done   bool
}

func main() {
	var (
		addr    = flag.String("addr", ":4242", "listen addr")
		outDir  = flag.String("out", "test_data", "output dir")
		timeout = flag.Duration("timeout", 1*time.Second, "idle timeout")
		// Polar selection flags (must match client). Default 3GPP.
		polarMode       = flag.String("polar-mode", "3gpp", "polar params: 3gpp|artifacts|runtime")
		polar3gppTable  = flag.String("polar-3gpp-table", "docs/polar_table_5_3_1_2_1_inverted.txt", "3GPP table path (index, rank; larger=more reliable)")
		polarArtifacts  = flag.String("polar-artifacts", "tables", "base dir of polar artifacts (per N,K,e)")
		polarArtifactsE = flag.Int("polar-art-e", 60, "artifacts epsilon bucket (e)")
		polarEps        = flag.Float64("polar-eps", 0.01, "runtime epsilon for BEC selection")
	)
	flag.Parse()

	tlsConf := generateTLSConfig()
	qconf := &quic.Config{EnableDatagrams: true, MaxIdleTimeout: *timeout}

	ln, err := quic.ListenAddr(*addr, tlsConf, qconf)
	if err != nil {
		fmt.Println("listen:", err)
		return
	}
	fmt.Println("listening on", *addr)

	// Accept connections sequentially to support multiple trials.
	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			fmt.Println("accept conn:", err)
			return
		}
		if err := handleConn(conn, *outDir, *timeout, *polarMode, *polar3gppTable, *polarArtifacts, *polarArtifactsE, *polarEps); err != nil {
			// Log and continue accepting next connections.
			fmt.Println("conn error:", err)
		}
	}
}

func handleConn(conn *quic.Conn, outDir string, timeout time.Duration, polarMode, polar3gppTable, polarArtifacts string, polarArtifactsE int, polarEps float64) error {
	defer conn.CloseWithError(0, "bye")

	// read metadata stream
	str, err := conn.AcceptStream(context.Background())
	if err != nil {
		return fmt.Errorf("accept stream: %w", err)
	}
	var m meta
	dec := json.NewDecoder(str)
	if err := dec.Decode(&m); err != nil {
		return fmt.Errorf("read meta: %w", err)
	}
	str.Close()

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	outPath := filepath.Join(outDir, m.Name+".recv")
	tmpPath := outPath + ".part"
	// Create a temporary file. Only rename to final path after successful finalize.
	outFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create out: %w", err)
	}
	fmt.Println("created output (temp):", tmpPath)

	// buffers per block
	blocks := make(map[uint16]*blockBuffer)
	totalWritten := 0

	// Helper: attempt to decode any ready blocks and write them out.
	tryDecode := func() {
		for bid, bb := range blocks {
			if bb.done {
				continue
			}
			recv := make([]fec.Packet, 0, len(bb.recv))
			for i := 0; i < m.K; i++ {
				if p, ok := bb.recv[i]; ok {
					recv = append(recv, p)
				}
			}
			for i := m.K; i < m.N; i++ {
				if p, ok := bb.recv[i]; ok {
					recv = append(recv, p)
				}
			}
			var src [][]byte
			var okd bool
			switch m.Scheme {
			case "rlc":
				if len(bb.recv) < m.K {
					continue
				}
				haveK := true
				for i := 0; i < m.K; i++ {
					if _, ok := bb.recv[i]; !ok {
						haveK = false
						break
					}
				}
				if haveK {
					buf := make([]byte, m.K*m.L)
					off := 0
					for i := 0; i < m.K; i++ {
						copy(buf[off:off+m.L], bb.recv[i].Data)
						off += m.L
					}
					src = make([][]byte, m.K)
					for i := 0; i < m.K; i++ {
						src[i] = buf[i*m.L : (i+1)*m.L]
					}
					okd = true
				} else {
					src, okd = fec.DecodeRLC(recv, m.K, "gf256")
				}
			case "rs":
				if len(bb.recv) < m.K {
					continue
				}
				src, okd = fec.DecodeRS(recv, m.K, m.N-m.K)
			case "raptorq":
				if len(recv) == 0 {
					continue
				}
				if bytes, ok := fec.RaptorQDecodeBytes(recv, m.N, m.K, m.L, bb.size); ok {
					src = [][]byte{bytes}
					okd = true
				}
			default:
				if len(bb.recv) < m.K {
					continue
				}
				var pp *fec.PacketPolarParams
				var err error
				switch polarMode {
				case "3gpp":
					pp, err = fec.NewPacketPolarParamsFrom3GPP(polar3gppTable, m.N, m.K, m.L)
				case "artifacts":
					pp, err = fec.NewPacketPolarParamsFromArtifacts(polarArtifacts, m.N, m.K, polarArtifactsE, m.L)
				case "runtime":
					pp, err = fec.NewPacketPolarParams(m.N, m.K, polarEps, m.L)
				default:
					fmt.Println("unknown polar-mode:", polarMode)
					continue
				}
				if err != nil {
					fmt.Println("polar params:", err)
					continue
				}
				src, okd = fec.PacketPolarDecode(pp, recv)
			}
			if okd {
				toWrite := bb.size
				var buf []byte
				if len(src) == 1 {
					buf = src[0]
					if len(buf) > toWrite {
						buf = buf[:toWrite]
					}
				} else {
					buf = make([]byte, toWrite)
					offw := 0
					for i := 0; i < m.K && offw < toWrite; i++ {
						need := toWrite - offw
						chunk := src[i]
						if len(chunk) > need {
							chunk = chunk[:need]
						}
						copy(buf[offw:offw+len(chunk)], chunk)
						offw += len(chunk)
					}
				}
				if _, err := outFile.WriteAt(buf, int64(bb.offset)); err != nil {
					fmt.Println("write out:", err)
					continue
				}
				bb.done = true
				totalWritten += toWrite
				delete(blocks, bid)
			}
		}
	}

	// Receive loop with idle decode cycles until an overall deadline expires.
	overall := timeout * 10
	if overall < 2*time.Second {
		overall = 2 * time.Second
	}
	deadline := time.Now().Add(overall)
	for totalWritten < m.Size {
		recvCtx, cancel := context.WithTimeout(context.Background(), timeout)
		d, err := conn.ReceiveDatagram(recvCtx)
		cancel()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				fmt.Println("idle timeout; attempting decode")
				tryDecode()
				if totalWritten >= m.Size {
					break
				}
				if time.Now().After(deadline) {
					fmt.Println("overall deadline reached; stopping receive")
					break
				}
				continue
			}
			fmt.Println("recv dgram:", err)
			break
		}
		if len(d) < fecwire.HeaderLen {
			continue
		}
		var hdr fecwire.FECHeader
		if !hdr.UnmarshalBinary(d[:fecwire.HeaderLen]) {
			continue
		}
		// Header sanity checks: values must match metadata
		if int(hdr.N) != m.N || int(hdr.K) != m.K {
			continue
		}
		payload := d[fecwire.HeaderLen:]
		if int(hdr.PayloadLen) > len(payload) {
			continue
		}
		// Validate payload length per scheme. RLC parity includes a K-byte coeff header (len=L+K).
		switch m.Scheme {
		case "rlc":
			if int(hdr.PayloadLen) != m.L && int(hdr.PayloadLen) != m.L+m.K {
				continue
			}
			payload = payload[:hdr.PayloadLen]
		case "raptorq":
			if int(hdr.PayloadLen) <= 0 || int(hdr.PayloadLen) > m.L {
				continue
			}
			payload = payload[:hdr.PayloadLen]
		default:
			if int(hdr.PayloadLen) != m.L {
				continue
			}
			payload = payload[:hdr.PayloadLen]
		}

		bb, ok := blocks[hdr.BlockID]
		if !ok {
			blockBytes := m.K * m.L
			off := int(hdr.BlockID) * blockBytes
			if off >= m.Size {
				continue
			}
			sz := blockBytes
			if left := m.Size - off; left < sz {
				sz = left
			}
			bb = &blockBuffer{recv: make(map[int]fec.Packet), offset: off, size: sz}
			blocks[hdr.BlockID] = bb
		}
		idx := int(hdr.SymID)
		pkt := fec.Packet{Index: idx, Data: append([]byte(nil), payload...)}
		bb.recv[idx] = pkt
	}

	// Final decode pass
	tryDecode()

	// Finalize: only if we fully recovered the file
	if totalWritten != m.Size {
		// best-effort cleanup
		_ = outFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("incomplete decode: wrote %d of %d bytes", totalWritten, m.Size)
	}
	_ = os.Truncate(tmpPath, int64(m.Size))
	if err := outFile.Sync(); err != nil {
		fmt.Println("sync:", err)
	}
	if err := outFile.Close(); err != nil {
		fmt.Println("close:", err)
	}
	if m.SHA256 != "" {
		if sum, err := fileSHA256(tmpPath); err == nil && sum != m.SHA256 {
			fmt.Println("sha256 mismatch (receiver)")
		}
	}
	// Atomically move into place
	if err := os.Rename(tmpPath, outPath); err != nil {
		return fmt.Errorf("rename final: %w", err)
	}
	fmt.Println("finalized output:", outPath)
	fmt.Println("wrote", m.Size, "bytes to", outPath)

	// Ack after finalize
	time.Sleep(50 * time.Millisecond)
	if s, err := conn.OpenStreamSync(context.Background()); err == nil {
		_, _ = s.Write([]byte{0xAA})
		_ = s.Close()
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		n, er := f.Read(buf)
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if er != nil {
			if er == io.EOF {
				break
			}
			return "", er
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// generateTLSConfig creates a self-signed ed25519 certificate at runtime.
func generateTLSConfig() *tls.Config {
	_, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: priv}}, NextProtos: []string{"quic-fec-demo"}}
}
