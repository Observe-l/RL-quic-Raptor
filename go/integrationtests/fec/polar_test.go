package fec

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"

	// quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/fec"
)

func TestPolar(t *testing.T) {
	// K := 32 // Number of data frames
	// const frameSize = 512

	// // 1. Generate K random data frames.
	// fmt.Printf("Generating K=%d random data frames...\n\n", K)
	// dataFrames := make([][]byte, K)
	// for i := 0; i < K; i++ {
	// 	dataFrames[i] = make([]byte, frameSize)
	// 	_, err := rand.Read(dataFrames[i])
	// 	if err != nil {
	// 		t.Fatalf("Failed to generate random frame %d: %v", i, err)
	// 	}
	// }

	// // 2. Run the full encoding pipeline.
	// encodingIndex, err := fec.LoadEncodingIndex("../../fec/encoding_index.bin")
	// if err != nil {
	// 	t.Fatalf("Failed to load encoding index: %v", err)
	// }
	// finalPackets, randomMap, originalCodewordsForVerification, err := fec.EncodeAndBitInterleaveFrames(dataFrames, encodingIndex)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// fmt.Println("\n--- Encoding Complete ---")
	// fmt.Printf("Output: %d packets, %d bytes/packet\n", len(finalPackets), len(finalPackets[0]))
	// fmt.Printf("Random INTRA-CODEWORD map size: %d elements\n", len(randomMap))

	// // --- 3. Run the Recovery Pipeline ---
	// fmt.Println("\n--- Starting Recovery ---")
	// recoveredCodewords, err := fec.DeinterleaveAndReassemble(finalPackets, randomMap)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// fmt.Println("\n--- Recovery Complete ---")
	// fmt.Printf("Reassembled %d codewords of %d bytes each.\n", len(recoveredCodewords), len(recoveredCodewords[0]))

	// // --- 4. Verification ---
	// fmt.Println("\n--- Verification ---")
	// if len(originalCodewordsForVerification) != len(recoveredCodewords) {
	// 	t.Fatalf("Verification failed: Mismatched number of codewords.")
	// }

	// // Compare the first and last codeword as a sanity check
	// if !bytes.Equal(originalCodewordsForVerification[0], recoveredCodewords[0]) {
	// 	t.Fatalf("Verification FAILED: First original and recovered codewords do not match!")
	// }
	// lastIdx := len(recoveredCodewords) - 1
	// if !bytes.Equal(originalCodewordsForVerification[lastIdx], recoveredCodewords[lastIdx]) {
	// 	t.Fatalf("Verification FAILED: Last original and recovered codewords do not match!")
	// }

	// fmt.Println("Verification PASSED: Original and recovered codewords match successfully!")

	// Load the reliability sequence from file.
	encodingIndex, err := fec.LoadEncodingIndex("../../fec/encoding_index.bin")
	if err != nil {
		t.Fatalf("Critical error: Could not load encoding_index.bin. Please ensure the file exists. %v", err)
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	// --- Setup ---
	K := 32 // Number of data frames
	const frameSize = 512
	fmt.Printf("\n--- Starting End-to-End Test (No Bit-Reversal) ---\n")
	fmt.Printf("Parameters: K=%d frames, Frame Size=%d bytes\n\n", K, frameSize)

	// 1. Generate K random data frames (the "ground truth").
	fmt.Printf("Generating K=%d random data frames...\n", K)
	originalDataFrames := make([][]byte, K)
	for i := 0; i < K; i++ {
		originalDataFrames[i] = make([]byte, frameSize)
		_, err := r.Read(originalDataFrames[i])
		if err != nil {
			t.Fatalf("Failed to generate random frame %d: %v", i, err)
		}
	}

	// 2. Run the full encoding and interleaving pipeline.
	fmt.Println("\n--- Starting Encoding Pipeline ---")
	finalPackets, randomMap, _, err := fec.EncodeAndBitInterleaveFrames(originalDataFrames, encodingIndex)
	if err != nil {
		t.Fatalf("Encoding pipeline failed: %v", err)
	}
	fmt.Println("--- Encoding Complete ---")

	// Drop exactly one random packet (simulate loss). Decoder treats missing bits as LLR=0.
	if len(finalPackets) != 32 {
		t.Fatalf("expected 32 packets, got %d", len(finalPackets))
	}
	dropIdx := int(originalDataFrames[0][0]) % 32 // deterministic but random-looking
	finalPackets[dropIdx] = nil                   // mark as lost

	// 3. Run the full recovery and decoding pipeline.
	recoveredDataFrames, err := fec.DecodeAndRecoverFrames(finalPackets, randomMap, encodingIndex)
	if err != nil {
		t.Fatalf("Decoding pipeline failed: %v", err)
	}
	fmt.Println("--- Recovery Complete ---")

	// 4. Verification.
	fmt.Println("\n--- Verification ---")
	if len(originalDataFrames) != len(recoveredDataFrames) {
		t.Fatalf("Verification FAILED: Mismatched number of frames. Original=%d, Recovered=%d", len(originalDataFrames), len(recoveredDataFrames))
	}
	for i := 0; i < K; i++ {
		if !bytes.Equal(originalDataFrames[i], recoveredDataFrames[i]) {
			t.Fatalf("Verification FAILED: Mismatch found in data frame %d!", i)
		}
	}

	fmt.Println("\n=========================================================")
	fmt.Println("  Verification PASSED: All recovered frames match the originals!")
	fmt.Println("=========================================================")
}
