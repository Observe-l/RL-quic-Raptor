package fec_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/quic-go/quic-go/fec"
)

func TestPolarPerformance_EncodeDecodeFile(t *testing.T) {
	root := repoRoot(t)
	srcPath := filepath.Join(root, "test_data", "train_FD001.txt")
	dstPath := filepath.Join(root, "test_data", "decode_FD001.txt")
	idxPath := filepath.Join(root, "fec", "encoding_index.bin")
	// --- Editable parameters (single place) ---
	n := 8             // exponent: N = 2^n
	Kbatch := 32       // packets per batch
	numDataBits := 256 // info bits per codeword
	drop_num := 10     // packets dropped per batch
	// ------------------------------------------

	Nbits := 1 << n
	mapPath := filepath.Join(root, "fec", fmt.Sprintf("random_map_%d.bin", Nbits))
	// Packet LUT persisted file (tied to n=10, kinfo, K; internal CRC binds to map contents)

	// Reset decode metrics for a clean run
	fec.ResetPolarDecodeStats()
	fec.ResetPolarPerfStats()

	// Load file
	src, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatalf("read src: %v", err)
	}

	// Load reliability indices
	encodingIndex, err := fec.LoadEncodingIndex(idxPath)
	if err != nil {
		t.Fatalf("load encoding index: %v", err)
	}

	// Print active parameters before encoding
	t.Logf("Params: n=%d, N=%d, Kbatch=%d, drops=%d, numDataBits=%d", n, Nbits, Kbatch, drop_num, numDataBits)
	fmt.Printf("Params: n=%d, N=%d, Kbatch=%d, drops=%d, numDataBits=%d\n", n, Nbits, Kbatch, drop_num, numDataBits)
	constBytes := numDataBits / 8
	msgSize := constBytes
	// Packet size equals Nbits/8 regardless of numDataBits; we keep 8 codewords per subset
	constMsgsPerSubset := 8
	numMsgsPerBatch := constMsgsPerSubset * Kbatch
	// droppackets per batch: already set in parameters above

	encTotal := time.Duration(0)
	decTotal := time.Duration(0)

	out := make([]byte, 0, len(src))
	// Try to load a persisted random map; if missing, we'll save after first encode
	// Require a pre-generated random map for this N to ensure stable, comparable perf.
	// Generate with: go run ./fec/tools/gen_random_map -n <N>
	persistedMap, err := fec.LoadRandomMap(mapPath, Nbits)
	if err != nil {
		t.Fatalf("missing random map for N=%d at %s: %v. Generate with: go run ./fec/tools/gen_random_map -n %d", Nbits, mapPath, err, Nbits)
	}
	// Use a different loss mask per batch to simulate real data transfer with varying losses.
	rgen := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Process the file in batches of messages
	for offset := 0; offset < len(src); {
		// Build up to numMsgsPerBatch messages (16 bytes each)
		msgs := make([][]byte, numMsgsPerBatch)
		msgsInBatch := 0
		for i := 0; i < numMsgsPerBatch; i++ {
			if offset >= len(src) {
				msgs[i] = make([]byte, msgSize) // zero padded
				continue
			}
			end := offset + msgSize
			if end > len(src) {
				end = len(src)
			}
			msg := make([]byte, msgSize)
			copy(msg, src[offset:end])
			msgs[i] = msg
			offset = end
			msgsInBatch++
		}

		// predeclare batch-scoped vars
		var packets [][]byte
		var randomMap []int
		// Track encode time per batch.
		encStart := time.Now()
		encEnd := encStart

		// Encode once
		packets, randomMap, err = fec.EncodeMsgsAndBitInterleaveN(msgs, encodingIndex, persistedMap, Kbatch, n)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		encEnd = time.Now()
		// Apply losses exactly as specified
		perm := rgen.Perm(Kbatch)
		for i := 0; i < drop_num && i < len(perm); i++ {
			packets[perm[i]] = nil
		}
		// Decode once (may fail as expected)
		t1 := time.Now()
		recMsgs, err := fec.DecodeMsgsN(packets, randomMap, encodingIndex, numDataBits, n)
		d := time.Since(t1)
		if err != nil {
			t.Fatalf("decode failed: %v", err)
		}
		decTotal += d
		encTotal += encEnd.Sub(encStart)

		// Append only the messages actually filled from the source
		for i := 0; i < msgsInBatch; i++ {
			out = append(out, recMsgs[i]...)
		}
	}

	if len(out) > len(src) {
		out = out[:len(src)]
	}
	if err := os.WriteFile(dstPath, out, 0o644); err != nil {
		t.Fatalf("write decoded: %v", err)
	}
	if !bytes.Equal(src, out) {
		t.Fatalf("decoded output mismatches input")
	}

	total := encTotal + decTotal
	stats := fec.GetPolarDecodeStats()
	p := fec.GetPolarPerfBreakdown()
	t.Logf("Polar encode time (total): %v", encTotal)
	t.Logf("Polar decode time (total) [%d drops of %d, %d bits]: %v", drop_num, Kbatch, numDataBits, decTotal)
	t.Logf("Total time: %v", total)
	t.Logf("Polar warm decode: total=%v, codewords=%d, avg warm per CW=%v", stats.WarmTotal, stats.WarmCodewords, stats.AvgWarmPerCW)
	t.Logf("Polar cold decode: total=%v, codewords=%d, avg cold per CW=%v", stats.ColdTotal, stats.ColdCodewords, stats.AvgColdPerCW)
	t.Logf("Polar phase breakdown: inv builds=%d total=%v avg/build=%v | Bbuild=%v, Mul=%v, Pack=%v | batches=%d totalCW=%d coldBatchCW=%d warmAvg/CW=%v coldAmort/CW=%v",
		p.InvBuilds, p.InvBuildTotal, p.AvgInvPerBuild, p.BBuildTotal, p.MulTotal, p.PackTotal,
		p.Batches, p.TotalCodewords, p.TotalColdBatchCWs, p.WarmAvgPerCW, p.ColdAmortizedPerCW)
	fmt.Printf("Polar encode(total)=%v, decode(total)=%v, total=%v\n", encTotal, decTotal, total)
	fmt.Printf("Polar warm: total=%v, CWs=%d, avgWarmPerCW=%v | cold: total=%v, CWs=%d, avgColdPerCW=%v\n", stats.WarmTotal, stats.WarmCodewords, stats.AvgWarmPerCW, stats.ColdTotal, stats.ColdCodewords, stats.AvgColdPerCW)
	fmt.Printf("Polar phases: inv builds=%d total=%v avg/build=%v | Bbuild=%v, Mul=%v, Pack=%v | batches=%d totalCW=%d coldBatchCW=%d warmAvg/CW=%v coldAmort/CW=%v\n",
		p.InvBuilds, p.InvBuildTotal, p.AvgInvPerBuild, p.BBuildTotal, p.MulTotal, p.PackTotal,
		p.Batches, p.TotalCodewords, p.TotalColdBatchCWs, p.WarmAvgPerCW, p.ColdAmortizedPerCW)
}
