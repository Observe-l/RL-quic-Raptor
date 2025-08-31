package fec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"math/rand"
	"os"
	"time"
)

// cache for info columns of G to avoid recomputation across batches
var (
	cachedGcols      [][]bool
	cachedInfoCols   []int
	cachedPolarN     int
	cachedPackedCols [][]uint64
	// Cached random map to keep interleaver stable across batches (enables cache hits)
	cachedRandMap  []int
	cachedRandMapK int
	// Cached interleave plan derived from randomMap for faster packet assembly
	cachedPlanMap []int
	cachedPlanK   int
	cachedPlan    [][][8]struct {
		srcByte int
		srcMask byte
	}
	// Packet-level LUT: for each message byte position (by) and byte value v (0..255),
	// a 128-byte slice representing the XOR contribution to all K packet bytes across subsets
	// (concatenated in subset order; each subset contributes subsetBytes = 1024/(8*K) bytes).
	cachedPacketLUT       [][]byte // indexed as [by*256 + v]
	cachedPacketLUTN      int
	cachedPacketLUTBits   int
	cachedPacketLUTK      int
	cachedPacketLUTMapRef []int
	// Inverse cache for multi-packet erasure keyed by loss mask and info size
	invCacheMap = make(map[struct {
		mask  uint32
		kinfo int
	}]struct {
		inv         [][]uint64
		usedRows    []int
		subsetBytes int
		// Per-selected-row metadata to speed RHS building on warm path
		rowInfo []struct {
			subset, byteOff int
			bitMask         byte
		}
	})
	// Cached inverse of randomMap for fast lookups
	cachedInvMap    []int
	cachedInvMapRef []int
)

// --- Decode metrics (warm vs cold) ---
// A "warm" decode means the inverse for the current loss mask was found in cache.
// A "cold" decode means we built and cached a new inverse.
var polarDecodeMetrics struct {
	warmTotal time.Duration
	coldTotal time.Duration
	warmCWs   int
	coldCWs   int
}

// Fine-grained phase metrics to avoid ambiguity
var polarPhaseMetrics struct {
	invBuilds   int
	invBuildTot time.Duration
	bBuildTot   time.Duration
	mulTot      time.Duration
	packTot     time.Duration
	batches     int
	totalCW     int
	coldCW      int // total CWs in batches where an inverse was built
}

// PolarPerfBreakdown exposes detailed decode timings.
type PolarPerfBreakdown struct {
	InvBuilds          int
	InvBuildTotal      time.Duration
	AvgInvPerBuild     time.Duration
	BBuildTotal        time.Duration
	MulTotal           time.Duration
	PackTotal          time.Duration
	Batches            int
	TotalCodewords     int
	TotalColdBatchCWs  int
	WarmAvgPerCW       time.Duration
	ColdAmortizedPerCW time.Duration
}

// GetPolarPerfBreakdown returns a snapshot of phase metrics.
func GetPolarPerfBreakdown() PolarPerfBreakdown {
	avgInv := time.Duration(0)
	if polarPhaseMetrics.invBuilds > 0 {
		avgInv = time.Duration(int64(polarPhaseMetrics.invBuildTot) / int64(polarPhaseMetrics.invBuilds))
	}
	warmDen := polarPhaseMetrics.totalCW
	warmAvg := time.Duration(0)
	if warmDen > 0 {
		warmAvg = time.Duration(int64(polarPhaseMetrics.bBuildTot+polarPhaseMetrics.mulTot+polarPhaseMetrics.packTot) / int64(warmDen))
	}
	coldAmort := time.Duration(0)
	if polarPhaseMetrics.coldCW > 0 {
		coldAmort = time.Duration(int64(polarPhaseMetrics.invBuildTot) / int64(polarPhaseMetrics.coldCW))
	}
	return PolarPerfBreakdown{
		InvBuilds:          polarPhaseMetrics.invBuilds,
		InvBuildTotal:      polarPhaseMetrics.invBuildTot,
		AvgInvPerBuild:     avgInv,
		BBuildTotal:        polarPhaseMetrics.bBuildTot,
		MulTotal:           polarPhaseMetrics.mulTot,
		PackTotal:          polarPhaseMetrics.packTot,
		Batches:            polarPhaseMetrics.batches,
		TotalCodewords:     polarPhaseMetrics.totalCW,
		TotalColdBatchCWs:  polarPhaseMetrics.coldCW,
		WarmAvgPerCW:       warmAvg,
		ColdAmortizedPerCW: coldAmort,
	}
}

// ResetPolarPerfStats clears the detailed decode metrics.
func ResetPolarPerfStats() {
	polarPhaseMetrics = struct {
		invBuilds   int
		invBuildTot time.Duration
		bBuildTot   time.Duration
		mulTot      time.Duration
		packTot     time.Duration
		batches     int
		totalCW     int
		coldCW      int
	}{}
}

// PolarDecodeStats is an exported snapshot of decode metrics.
type PolarDecodeStats struct {
	WarmTotal     time.Duration
	ColdTotal     time.Duration
	WarmCodewords int
	ColdCodewords int
	AvgWarmPerCW  time.Duration
	AvgColdPerCW  time.Duration
}

// GetPolarDecodeStats returns a snapshot of current warm/cold decode metrics.
func GetPolarDecodeStats() PolarDecodeStats {
	avgCold := time.Duration(0)
	avgWarm := time.Duration(0)
	if polarDecodeMetrics.coldCWs > 0 {
		// average cold time per codeword
		avgCold = time.Duration(int64(polarDecodeMetrics.coldTotal) / int64(polarDecodeMetrics.coldCWs))
	}
	if polarDecodeMetrics.warmCWs > 0 {
		// average warm time per codeword
		avgWarm = time.Duration(int64(polarDecodeMetrics.warmTotal) / int64(polarDecodeMetrics.warmCWs))
	}
	return PolarDecodeStats{
		WarmTotal:     polarDecodeMetrics.warmTotal,
		ColdTotal:     polarDecodeMetrics.coldTotal,
		WarmCodewords: polarDecodeMetrics.warmCWs,
		ColdCodewords: polarDecodeMetrics.coldCWs,
		AvgWarmPerCW:  avgWarm,
		AvgColdPerCW:  avgCold,
	}

}

// ResetPolarDecodeStats clears accumulated decode metrics.
func ResetPolarDecodeStats() {
	polarDecodeMetrics = struct {
		warmTotal time.Duration
		coldTotal time.Duration
		warmCWs   int
		coldCWs   int
	}{}
}

func getInfoColsAndG(n int, encodingIndex []int, numDataBits int) ([][]bool, []int) {
	if cachedGcols != nil && cachedPolarN == n && len(cachedInfoCols) == numDataBits {
		return cachedGcols, cachedInfoCols
	}
	// Build infoCols by taking entries from encodingIndex that fall within [0, N).
	// This allows using a universal reliability sequence file for different N.
	N := 1 << n
	infoCols := make([]int, 0, numDataBits)
	for _, idx := range encodingIndex {
		if idx < N {
			infoCols = append(infoCols, bitReverseN(idx, n))
			if len(infoCols) == numDataBits {
				break
			}
		}
	}
	if len(infoCols) != numDataBits {
		// Not enough indices < N to satisfy request.
		// Fall back to original behavior (unsafe) to avoid panic, but this likely indicates a bad config.
		infoCols = make([]int, numDataBits)
		for i := 0; i < numDataBits; i++ {
			infoCols[i] = bitReverseN(encodingIndex[i], n)
		}
	}
	Gcols := make([][]bool, numDataBits)
	for c := 0; c < numDataBits; c++ {
		j := infoCols[c]
		u := make([]bool, N)
		u[j] = true
		for s := 0; s < n; s++ {
			block := 1 << (s + 1)
			half := 1 << s
			for start := 0; start < N; start += block {
				for k := 0; k < half; k++ {
					i1 := start + k
					i2 := i1 + half
					u[i1] = u[i1] != u[i2]
				}
			}
		}
		Gcols[c] = u
	}
	cachedGcols = Gcols
	cachedInfoCols = infoCols
	cachedPolarN = n
	// Invalidate packed cache when the shape changes
	cachedPackedCols = nil
	return Gcols, infoCols
}

// getPackedInfoCols returns the packed columns (uint64 words) for fast encoding.
func getPackedInfoCols(n int, encodingIndex []int, numDataBits int) ([][]uint64, []int) {
	if cachedPackedCols != nil && cachedPolarN == n && len(cachedInfoCols) == numDataBits {
		return cachedPackedCols, cachedInfoCols
	}
	Gcols, infoCols := getInfoColsAndG(n, encodingIndex, numDataBits)
	packed := make([][]uint64, numDataBits)
	for i := 0; i < numDataBits; i++ {
		packed[i] = packBoolVec(Gcols[i])
	}
	cachedPackedCols = packed
	return packed, infoCols
}

// getStableRandomMap returns a deterministic random permutation of [0..codewordBits-1]
// using a fixed seed, cached by K to align subset partitioning.
func getStableRandomMap(codewordBits, K int) []int {
	// Also bind to codewordBits length; different N must rebuild.
	if cachedRandMap != nil && cachedRandMapK == K && len(cachedRandMap) == codewordBits {
		return cachedRandMap
	}
	r := rand.New(rand.NewSource(1)) // fixed seed for stability
	m := r.Perm(codewordBits)
	cachedRandMap = m
	cachedRandMapK = K
	// Invalidate interleave plan cache when map or K changes
	cachedPlanMap = nil
	cachedPlan = nil
	return m
}

// buildInterleavePlan precomputes, for each subset and each subset byte position,
// the 8 (srcByte,srcMask) pairs to assemble that destination byte from the codeword bytes.
func buildInterleavePlan(randomMap []int, K int) [][][8]struct {
	srcByte int
	srcMask byte
} {
	if cachedPlanMap != nil && cachedPlanK == K && len(cachedPlanMap) == len(randomMap) {
		same := true
		for i := range randomMap {
			if randomMap[i] != cachedPlanMap[i] {
				same = false
				break
			}
		}
		if same {
			return cachedPlan
		}
	}
	codewordBits := len(randomMap)
	subsetSizeBits := codewordBits / K
	subsetBytes := subsetSizeBits / 8
	plan := make([][][8]struct {
		srcByte int
		srcMask byte
	}, K)
	for s := 0; s < K; s++ {
		arr := make([][8]struct {
			srcByte int
			srcMask byte
		}, subsetBytes)
		for j := 0; j < subsetBytes; j++ {
			var e [8]struct {
				srcByte int
				srcMask byte
			}
			for b := 0; b < 8; b++ {
				destBit := s*subsetSizeBits + j*8 + b
				src := randomMap[destBit]
				e[b].srcByte = src >> 3
				e[b].srcMask = 1 << uint(src&7)
			}
			arr[j] = e
		}
		plan[s] = arr
	}
	cachedPlanMap = append([]int(nil), randomMap...)
	cachedPlanK = K
	cachedPlan = plan
	return plan
}

// getPacketLUT builds or returns a cached fused encode-to-packets LUT.
// For each message byte position 'by' and each byte value 'v', it precomputes the 128-byte
// contribution across all K subsets (concatenated), so encoding becomes XOR of these slices.
func getPacketLUT(n int, encodingIndex []int, numDataBits int, randomMap []int, K int) ([][]byte, error) {
	if cachedPacketLUT != nil && cachedPacketLUTN == n && cachedPacketLUTBits == numDataBits && cachedPacketLUTK == K &&
		cachedPacketLUTMapRef != nil && len(cachedPacketLUTMapRef) == len(randomMap) {
		same := true
		for i := range randomMap {
			if randomMap[i] != cachedPacketLUTMapRef[i] {
				same = false
				break
			}
		}
		if same {
			return cachedPacketLUT, nil
		}
	}
	codewordBits := 1 << n
	if numDataBits%8 != 0 {
		return nil, errors.New("numDataBits must be multiple of 8")
	}
	msgBytes := numDataBits / 8
	packedCols, _ := getPackedInfoCols(n, encodingIndex, numDataBits)
	words := codewordBits / 64
	// Precompute mapping from destBit i to source word/mask via randomMap
	type wm struct {
		w int
		m uint64
	}
	wmt := make([]wm, codewordBits)
	for i := 0; i < codewordBits; i++ {
		src := randomMap[i]
		wmt[i] = wm{w: src >> 6, m: 1 << uint(src&63)}
	}
	lut := make([][]byte, msgBytes*256)
	acc := make([]uint64, words)
	for by := 0; by < msgBytes; by++ {
		base := by * 8
		for v := 0; v < 256; v++ {
			row := make([]byte, codewordBits/8)
			if v != 0 {
				// build acc = XOR of selected columns
				for i := 0; i < words; i++ {
					acc[i] = 0
				}
				vv := v
				for bit := 0; bit < 8; bit++ {
					if (vv>>bit)&1 == 1 {
						col := packedCols[base+bit]
						for w := 0; w < words; w++ {
							acc[w] ^= col[w]
						}
					}
				}
				// map to destination ordering and pack into bytes
				for i := 0; i < codewordBits; i++ {
					wm := wmt[i]
					if acc[wm.w]&wm.m != 0 {
						row[i>>3] |= 1 << uint(i&7)
					}
				}
			}
			lut[by*256+v] = row
		}
	}
	cachedPacketLUT = lut
	cachedPacketLUTN = n
	cachedPacketLUTBits = numDataBits
	cachedPacketLUTK = K
	cachedPacketLUTMapRef = append([]int(nil), randomMap...)
	return lut, nil
}

// LoadRandomMap reads a binary file of little-endian int64 entries for the random map.
func LoadRandomMap(filePath string, N int) ([]int, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	if len(b)%8 != 0 {
		return nil, errors.New("random map file size invalid")
	}
	cnt := len(b) / 8
	if cnt != N {
		return nil, errors.New("random map length mismatch")
	}
	vals64 := make([]int64, cnt)
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &vals64); err != nil {
		return nil, err
	}
	vals := make([]int, cnt)
	for i, v := range vals64 {
		vals[i] = int(v)
	}
	return vals, nil
}

// SaveRandomMap writes the random map to a file as little-endian int64 values.
func SaveRandomMap(filePath string, m []int) error {
	vals64 := make([]int64, len(m))
	for i, v := range m {
		vals64[i] = int64(v)
	}
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, vals64); err != nil {
		return err
	}
	return os.WriteFile(filePath, buf.Bytes(), 0o644)
}

func invertBoolMatrixGF2(A [][]bool) ([][]bool, bool) {
	n := len(A)
	aug := make([][]bool, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]bool, 2*n)
		copy(aug[i][:n], A[i])
		aug[i][n+i] = true
	}
	row := 0
	for col := 0; col < n && row < n; col++ {
		pivot := -1
		for r := row; r < n; r++ {
			if aug[r][col] {
				pivot = r
				break
			}
		}
		if pivot == -1 {
			continue
		}
		aug[row], aug[pivot] = aug[pivot], aug[row]
		for r := 0; r < n; r++ {
			if r == row {
				continue
			}
			if aug[r][col] {
				for j := 0; j < 2*n; j++ {
					aug[r][j] = aug[r][j] != aug[row][j]
				}
			}
		}
		row++
	}
	if row < n {
		return nil, false
	}
	inv := make([][]bool, n)
	for i := 0; i < n; i++ {
		inv[i] = make([]bool, n)
		copy(inv[i], aug[i][n:])
	}
	return inv, true
}

func matVecGF2(A [][]bool, x []bool) []bool {
	n := len(A)
	y := make([]bool, n)
	for i := 0; i < n; i++ {
		var b bool
		for j := 0; j < n; j++ {
			if A[i][j] && x[j] {
				b = !b
			}
		}
		y[i] = b
	}
	return y
}

// packBoolRows packs a boolean matrix into uint64 word rows (LSB-first within a word).

func packBoolVec(v []bool) []uint64 {
	w := (len(v) + 63) / 64
	out := make([]uint64, w)
	for i, b := range v {
		if b {
			out[i>>6] |= 1 << (uint(i) & 63)
		}
	}
	return out
}

// matVecGF2Packed computes y = M * v over GF(2), with M rows and K columns, packed in uint64.
// (matVecGF2Packed removed: unused)

// invertBoolMatrixGF2Packed inverts a KxK boolean matrix using packed 64-bit words.
func invertBoolMatrixGF2Packed(A [][]bool) ([][]uint64, bool) {
	K := len(A)
	if K == 0 {
		return nil, false
	}
	w := (K + 63) / 64
	// Build augmented matrix [A | I] packed into uint64 words per row (2*w words per row)
	aug := make([][]uint64, K)
	for i := 0; i < K; i++ {
		row := make([]uint64, 2*w)
		// left A
		for j, v := range A[i] {
			if v {
				row[j>>6] |= 1 << (uint(j) & 63)
			}
		}
		// right I
		row[w+(i>>6)] |= 1 << (uint(i) & 63)
		aug[i] = row
	}
	r := 0
	for c := 0; c < K && r < K; c++ {
		wordIdx := c >> 6
		bitMask := uint64(1) << (uint(c) & 63)
		// find pivot
		p := -1
		for i := r; i < K; i++ {
			if aug[i][wordIdx]&bitMask != 0 {
				p = i
				break
			}
		}
		if p == -1 {
			continue
		}
		// swap rows
		aug[r], aug[p] = aug[p], aug[r]
		// eliminate this column in all other rows
		for i := 0; i < K; i++ {
			if i == r {
				continue
			}
			if aug[i][wordIdx]&bitMask != 0 {
				for wj := 0; wj < 2*w; wj++ {
					aug[i][wj] ^= aug[r][wj]
				}
			}
		}
		r++
	}
	if r < K {
		return nil, false
	}
	// Extract right side as inverse
	inv := make([][]uint64, K)
	for i := 0; i < K; i++ {
		row := make([]uint64, w)
		copy(row, aug[i][w:])
		inv[i] = row
	}
	return inv, true
}

// selectPivotRows chooses K linearly independent rows from A (MxK) using Gaussian elimination,
// and returns their indices relative to A. Returns ok=false if rank < K.
func selectPivotRows(A [][]bool, K int) ([]int, bool) {
	M := len(A)
	if M < K {
		return nil, false
	}
	// Make a copy so we can eliminate without mutating the original rows.
	work := make([][]bool, M)
	idxs := make([]int, M)
	for i := 0; i < M; i++ {
		work[i] = append([]bool(nil), A[i]...)
		idxs[i] = i
	}
	r := 0
	pivots := make([]int, 0, K)
	for c := 0; c < K && r < M; c++ {
		p := -1
		for i := r; i < M; i++ {
			if work[i][c] {
				p = i
				break
			}
		}
		if p == -1 {
			continue
		}
		work[r], work[p] = work[p], work[r]
		idxs[r], idxs[p] = idxs[p], idxs[r]
		for i := 0; i < M; i++ {
			if i == r {
				continue
			}
			if work[i][c] {
				for j := c; j < K; j++ {
					work[i][j] = work[i][j] != work[r][j]
				}
			}
		}
		pivots = append(pivots, idxs[r])
		r++
	}
	if len(pivots) < K {
		return nil, false
	}
	return pivots, true
}

// LoadEncodingIndex reads a binary file containing a sequence of little-endian int64 values
// and converts them to a slice of int for use as array indices.
func LoadEncodingIndex(filePath string) ([]int, error) {
	fileBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, errors.New("failed to read encoding index file")
	}

	int64Size := 8
	if len(fileBytes)%int64Size != 0 {
		return nil, errors.New("file size is not a multiple of int64 size")
	}

	arrayLen := len(fileBytes) / int64Size
	goSlice64 := make([]int64, arrayLen)
	reader := bytes.NewReader(fileBytes)
	if err := binary.Read(reader, binary.LittleEndian, &goSlice64); err != nil {
		return nil, errors.New("failed to decode binary data")
	}

	// Convert []int64 to []int for direct use as slice indices.
	goSliceInt := make([]int, arrayLen)
	for i, v := range goSlice64 {
		goSliceInt[i] = int(v)
	}
	return goSliceInt, nil
}

// EncodePolarGN encodes the input data using the standard polar generator matrix G_N = B_N * F^{⊗n}.
//
// Parameters:
//   - data: The input message data to encode (64 bytes = 512 bits in your case).
//   - n: The exponent for the polar code (n=10 in your case).
//
// Returns:
//   - A byte slice containing the encoded codeword of length N/8.
//   - An error if the input parameters are invalid.
func EncodePolarGN(data []byte, n int, encodingIndex []int) ([]byte, error) {
	dataBits := len(data) * 8
	N := 1 << n
	// Build the information positions using only indices within [0, N).
	infoPos := make([]int, 0, dataBits)
	for _, idx := range encodingIndex {
		if idx < N {
			infoPos = append(infoPos, bitReverseN(idx, n))
			if len(infoPos) == dataBits {
				break
			}
		}
	}
	if len(infoPos) != dataBits {
		return nil, errors.New("not enough reliability indices for this N and data size")
	}
	// Create the information vector 'u' using the reliability sequence.
	u := make([]bool, N)
	bitCounter := 0
	for _, byteVal := range data {
		for j := 0; j < 8; j++ {
			destIndex := infoPos[bitCounter]
			bitValue := (byteVal>>j)&1 == 1
			u[destIndex] = bitValue
			bitCounter++
		}
	}
	// We apply the transform directly to the information vector 'u'.
	x := u
	for i := uint(0); i < uint(n); i++ {
		blockSize := 1 << (i + 1)
		halfBlock := 1 << i
		for blockStart := 0; blockStart < N; blockStart += blockSize {
			for j := 0; j < halfBlock; j++ {
				idx1 := blockStart + j
				idx2 := idx1 + halfBlock
				x[idx1] = x[idx1] != x[idx2]
			}
		}
	}
	// Pack the bits into bytes.
	encodedBytes := make([]byte, N/8)
	for i := range encodedBytes {
		var packedByte byte
		for j := range 8 {
			if x[i*8+j] {
				packedByte |= (1 << j)
			}
		}
		encodedBytes[i] = packedByte
	}
	return encodedBytes, nil
}

// --- Main Pipeline Function with Bit-Level Shuffling ---

// EncodeAndBitInterleaveFrames performs segmentation, polar encoding, and bit-level interleaving.
func EncodeAndBitInterleaveFrames(dataFrames [][]byte, encodingIndex []int) (finalPackets [][]byte, randomMap []int, allCodewordsForVerification [][]byte, err error) {
	K := len(dataFrames)
	if K == 0 || (K&(K-1)) != 0 {
		return nil, nil, nil, errors.New("k must be a non-zero power of 2")
	}
	const frameSize = 512
	const chunkSize = 64
	const codewordBytes = 128
	const codewordBits = codewordBytes * 8
	const chunksPerFrame = frameSize / chunkSize
	const polarN = 10
	numCodewords := K * chunksPerFrame
	allCodewords := make([][]byte, 0, numCodewords)
	for _, frame := range dataFrames {
		if len(frame) != frameSize {
			return nil, nil, nil, errors.New("invalid size for frame")
		}
		for i := 0; i < chunksPerFrame; i++ {
			chunk := frame[i*chunkSize : (i+1)*chunkSize]
			encodedChunk, err := EncodePolarGN(chunk, polarN, encodingIndex)
			if err != nil {
				return nil, nil, nil, errors.New("encoding failed")
			}
			allCodewords = append(allCodewords, encodedChunk)
		}
	}
	// Use a stable random map so the missing packet index corresponds to a fixed row set across batches
	randomMap = getStableRandomMap(codewordBits, K)
	subsetSizeBits := codewordBits / K
	outputPacketSizeBits := numCodewords * subsetSizeBits
	outputPacketsBits := make([][]bool, K)
	for i := range outputPacketsBits {
		outputPacketsBits[i] = make([]bool, outputPacketSizeBits)
	}
	codewordBitsUnpacked := make([]bool, codewordBits)
	shuffledBits := make([]bool, codewordBits)
	for cwIdx, codewordBytes := range allCodewords {
		for i, byteVal := range codewordBytes {
			for j := 0; j < 8; j++ {
				codewordBitsUnpacked[i*8+j] = (byteVal>>j)&1 == 1
			}
		}
		for i := 0; i < codewordBits; i++ {
			shuffledBits[i] = codewordBitsUnpacked[randomMap[i]]
		}
		for subsetIdx := 0; subsetIdx < K; subsetIdx++ {
			subsetStart := subsetIdx * subsetSizeBits
			subset := shuffledBits[subsetStart : subsetStart+subsetSizeBits]
			destPacketBits := outputPacketsBits[subsetIdx]
			destStartOffset := cwIdx * subsetSizeBits
			copy(destPacketBits[destStartOffset:], subset)
		}
	}
	finalPackets = make([][]byte, K)
	outputPacketSizeBytes := outputPacketSizeBits / 8
	for i := 0; i < K; i++ {
		packetBytes := make([]byte, outputPacketSizeBytes)
		for j := 0; j < outputPacketSizeBytes; j++ {
			var packedByte byte
			for bitOffset := 0; bitOffset < 8; bitOffset++ {
				if outputPacketsBits[i][j*8+bitOffset] {
					packedByte |= (1 << bitOffset)
				}
			}
			packetBytes[j] = packedByte
		}
		finalPackets[i] = packetBytes
	}
	return finalPackets, randomMap, allCodewords, nil
}

// EncodeMsgsAndBitInterleave encodes arbitrary-size messages (len in bytes, multiple of 1 byte) into 1024-bit codewords
// and interleaves bits across K packets according to randomMap. If randomMap is nil, a stable one is generated.
func EncodeMsgsAndBitInterleave(msgs [][]byte, encodingIndex []int, randomMap []int, K int) ([][]byte, []int, error) {
	return EncodeMsgsAndBitInterleaveN(msgs, encodingIndex, randomMap, K, 10)
}

// EncodeMsgsAndBitInterleaveN encodes arbitrary-size messages into N=2^n bit codewords
// and interleaves bits across K packets according to randomMap. If randomMap is nil, a stable one is generated.
func EncodeMsgsAndBitInterleaveN(msgs [][]byte, encodingIndex []int, randomMap []int, K int, n int) ([][]byte, []int, error) {
	if K == 0 || (K&(K-1)) != 0 {
		return nil, nil, errors.New("k must be power of 2")
	}
	const minN = 1
	if n < minN {
		return nil, nil, errors.New("invalid n")
	}
	codewordBits := 1 << n
	numCodewords := len(msgs)
	codewords := make([][]byte, numCodewords)
	// Fast path: if all messages have same length, precompute packed columns and XOR
	uniform := numCodewords > 0
	msgBits := 0
	if uniform {
		msgBits = len(msgs[0]) * 8
	}
	// for i := 1; i < numCodewords && uniform; i++ {
	// 	if len(msgs[i]) != len(msgs[0]) {
	// 		uniform = false
	// 	}
	// }
	if uniform && msgBits > 0 {
		if msgBits > len(encodingIndex) {
			return nil, nil, errors.New("encodingIndex too short for msg")
		}
		// Ensure randomMap is available for fused encoder path
		if randomMap == nil {
			randomMap = getStableRandomMap(codewordBits, K)
		}
		// Fused path: directly XOR packet LUT rows into packets, skipping codeword materialization
		subsetSizeBits := codewordBits / K
		subsetBytes := subsetSizeBits / 8
		outBytes := (numCodewords * subsetSizeBits) / 8
		packets := make([][]byte, K)
		for i := 0; i < K; i++ {
			packets[i] = make([]byte, outBytes)
		}
		pktLUT, err := getPacketLUT(n, encodingIndex, msgBits, randomMap, K)
		if err != nil {
			return nil, nil, err
		}
		msgBytes := msgBits / 8
		for cwIdx := 0; cwIdx < numCodewords; cwIdx++ {
			m := msgs[cwIdx]
			baseOff := cwIdx * subsetBytes
			for by := 0; by < msgBytes; by++ {
				v := int(m[by])
				if v == 0 {
					continue
				}
				row := pktLUT[by*256+v] // 128 bytes across K subsets
				// XOR into each subset at codeword offset
				for s := 0; s < K; s++ {
					dst := packets[s][baseOff : baseOff+subsetBytes]
					src := row[s*subsetBytes : (s+1)*subsetBytes]
					for j := 0; j < subsetBytes; j++ {
						dst[j] ^= src[j]
					}
				}
			}
		}
		return packets, randomMap, nil
	} else {
		for i, m := range msgs {
			if (len(m) * 8) > len(encodingIndex) {
				return nil, nil, errors.New("encodingIndex too short for msg")
			}
			cw, err := EncodePolarGN(m, n, encodingIndex)
			if err != nil {
				return nil, nil, err
			}
			codewords[i] = cw
		}
	}
	if randomMap == nil {
		randomMap = getStableRandomMap(codewordBits, K)
	}
	subsetSizeBits := codewordBits / K
	outputPacketSizeBits := numCodewords * subsetSizeBits
	// Prepare byte-wise packet buffers
	packets := make([][]byte, K)
	outBytes := outputPacketSizeBits / 8
	for i := 0; i < K; i++ {
		packets[i] = make([]byte, outBytes)
	}
	// Use a precomputed interleave plan to assemble packet bytes efficiently
	plan := buildInterleavePlan(randomMap, K)
	subsetBytes := subsetSizeBits / 8
	for subset := 0; subset < K; subset++ {
		rows := plan[subset]
		dst := packets[subset]
		for cwIdx, cw := range codewords {
			dstBase := cwIdx * subsetBytes
			for j := 0; j < subsetBytes; j++ {
				var outb byte
				e := rows[j]
				if cw[e[0].srcByte]&e[0].srcMask != 0 {
					outb |= 1 << 0
				}
				if cw[e[1].srcByte]&e[1].srcMask != 0 {
					outb |= 1 << 1
				}
				if cw[e[2].srcByte]&e[2].srcMask != 0 {
					outb |= 1 << 2
				}
				if cw[e[3].srcByte]&e[3].srcMask != 0 {
					outb |= 1 << 3
				}
				if cw[e[4].srcByte]&e[4].srcMask != 0 {
					outb |= 1 << 4
				}
				if cw[e[5].srcByte]&e[5].srcMask != 0 {
					outb |= 1 << 5
				}
				if cw[e[6].srcByte]&e[6].srcMask != 0 {
					outb |= 1 << 6
				}
				if cw[e[7].srcByte]&e[7].srcMask != 0 {
					outb |= 1 << 7
				}
				dst[dstBase+j] = outb
			}
		}
	}
	return packets, randomMap, nil
}

// DeinterleaveKnownGeneric reconstructs codeword bits from packets for arbitrary batch size.
func DeinterleaveKnownGeneric(interleavedPackets [][]byte, randomMap []int) ([][]bool, error) {
	K := len(interleavedPackets)
	if K == 0 {
		return nil, errors.New("no packets")
	}
	codewordBits := len(randomMap)
	subsetSizeBits := codewordBits / K
	// infer numCodewords from packet size
	var pktLen int
	for _, p := range interleavedPackets {
		if len(p) > 0 {
			pktLen = len(p)
			break
		}
	}
	if pktLen == 0 {
		return nil, errors.New("all packets missing")
	}
	totalBits := pktLen * 8
	if totalBits%subsetSizeBits != 0 {
		return nil, errors.New("packet size invalid for K")
	}
	numCodewords := totalBits / subsetSizeBits
	// unpack
	pktBits := make([][]bool, K)
	present := make([]bool, K)
	for i, p := range interleavedPackets {
		if len(p) == 0 {
			present[i] = false
			continue
		}
		present[i] = true
		bits := make([]bool, len(p)*8)
		for j, by := range p {
			for b := 0; b < 8; b++ {
				bits[j*8+b] = ((by >> b) & 1) == 1
			}
		}
		pktBits[i] = bits
	}
	// gather shuffled
	shuffled := make([][]bool, numCodewords)
	for cw := 0; cw < numCodewords; cw++ {
		s := make([]bool, codewordBits)
		for subset := 0; subset < K; subset++ {
			start := subset * subsetSizeBits
			if present[subset] {
				src := pktBits[subset]
				off := cw * subsetSizeBits
				copy(s[start:start+subsetSizeBits], src[off:off+subsetSizeBits])
			}
		}
		shuffled[cw] = s
	}
	// de-shuffle
	inv := invertMap(randomMap)
	out := make([][]bool, numCodewords)
	for cw := 0; cw < numCodewords; cw++ {
		b := make([]bool, codewordBits)
		for i := 0; i < codewordBits; i++ {
			b[i] = shuffled[cw][inv[i]]
		}
		out[cw] = b
	}
	return out, nil
}

// DecodeMsgs decodes variable-size messages (numDataBits) from interleaved packets using algebraic erasure decoding.
func DecodeMsgs(interleavedPackets [][]byte, randomMap, encodingIndex []int, numDataBits int) ([][]byte, error) {
	return DecodeMsgsN(interleavedPackets, randomMap, encodingIndex, numDataBits, 10)
}

// DecodeMsgsN decodes variable-size messages from interleaved packets using algebraic erasure decoding for N=2^n.
func DecodeMsgsN(interleavedPackets [][]byte, randomMap, encodingIndex []int, numDataBits int, n int) ([][]byte, error) {
	totalStart := time.Now()
	K := len(interleavedPackets)
	// We route both loss and no-loss cases through the packed algebraic path for speed and consistency.
	N := 1 << n
	// Build presence and known rows using inverse map
	subsetSizeBits := N / K
	var mask uint32
	present := make([]bool, K)
	for i, p := range interleavedPackets {
		if len(p) == 0 {
			mask |= 1 << uint(i)
		} else {
			present[i] = true
		}
	}
	// Get cached inverse map
	var inv []int
	if cachedInvMap != nil && cachedInvMapRef != nil && len(cachedInvMapRef) == len(randomMap) {
		same := true
		for i := range randomMap {
			if randomMap[i] != cachedInvMapRef[i] {
				same = false
				break
			}
		}
		if same {
			inv = cachedInvMap
		} else {
			inv = invertMap(randomMap)
			cachedInvMap = inv
			cachedInvMapRef = append([]int(nil), randomMap...)
		}
	} else {
		inv = invertMap(randomMap)
		cachedInvMap = inv
		cachedInvMapRef = append([]int(nil), randomMap...)
	}
	// We don't need to materialize the full list of known rows here; we'll select rows on the fly.
	// Helper to build B directly from packets for selected rows
	buildB := func(usedRows []int) (B [][]uint64, numCW int) {
		// infer num codewords from any present packet
		var pktLen int
		for i := 0; i < K; i++ {
			if present[i] {
				pktLen = len(interleavedPackets[i])
				break
			}
		}
		totalBits := pktLen * 8
		numCW = totalBits / subsetSizeBits
		wordsCW := (numCW + 63) / 64
		subsetBytes := subsetSizeBits / 8
		// Precompute tuple (subset, byteOff, bitMask) per used row
		type sbm struct {
			subset, byteOff int
			bitMask         byte
		}
		rowInfo := make([]sbm, numDataBits)
		for c := 0; c < numDataBits; c++ {
			r := usedRows[c]
			s := inv[r]
			subset := s / subsetSizeBits
			within := s % subsetSizeBits
			rowInfo[c] = sbm{subset: subset, byteOff: within >> 3, bitMask: 1 << uint(within&7)}
		}
		B = make([][]uint64, numDataBits)
		for c := 0; c < numDataBits; c++ {
			info := rowInfo[c]
			row := make([]uint64, wordsCW)
			if present[info.subset] {
				pkt := interleavedPackets[info.subset]
				base := info.byteOff
				for cw := 0; cw < numCW; cw++ {
					idx := cw*subsetBytes + base
					if pkt[idx]&info.bitMask != 0 {
						row[cw>>6] |= 1 << uint(cw&63)
					}
				}
			}
			B[c] = row
		}
		return B, numCW
	}
	// Helper: compute Out = inv * B over GF(2) (single-threaded for fair comparison)
	computeOut := func(inv [][]uint64, B [][]uint64, wordsCW int, k int) [][]uint64 {
		Out := make([][]uint64, k)
		for i := 0; i < k; i++ {
			acc := make([]uint64, wordsCW)
			for pb := 0; pb < len(inv[i]); pb++ {
				m := inv[i][pb]
				for m != 0 {
					tz := bits.TrailingZeros64(m)
					col := (pb << 6) + tz
					brow := B[col]
					for w := 0; w < wordsCW; w++ {
						acc[w] ^= brow[w]
					}
					m &= m - 1
				}
			}
			Out[i] = acc
		}
		return Out
	}

	// Check cache
	if e, ok := invCacheMap[struct {
		mask  uint32
		kinfo int
	}{mask: mask, kinfo: numDataBits}]; ok {
		invAsqPacked := e.inv
		usedRows := e.usedRows
		// Build B directly from packets using cached rowInfo when available
		var B [][]uint64
		var numCW int
		if e.rowInfo != nil && e.subsetBytes > 0 {
			// warm fast path with precomputed offsets
			// infer num codewords
			var pktLen int
			for i := 0; i < K; i++ {
				if present[i] {
					pktLen = len(interleavedPackets[i])
					break
				}
			}
			totalBits := pktLen * 8
			numCW = totalBits / subsetSizeBits
			wordsCW := (numCW + 63) / 64
			B = make([][]uint64, numDataBits)
			tBStart := time.Now()
			for c := 0; c < numDataBits; c++ {
				info := e.rowInfo[c]
				row := make([]uint64, wordsCW)
				if present[info.subset] {
					pkt := interleavedPackets[info.subset]
					base := info.byteOff
					for cw := 0; cw < numCW; cw++ {
						idx := cw*e.subsetBytes + base
						if pkt[idx]&info.bitMask != 0 {
							row[cw>>6] |= 1 << uint(cw&63)
						}
					}
				}
				B[c] = row
			}
			polarPhaseMetrics.bBuildTot += time.Since(tBStart)
		} else {
			tBStart := time.Now()
			B, numCW = buildB(usedRows)
			polarPhaseMetrics.bBuildTot += time.Since(tBStart)
		}
		wordsCW := (numCW + 63) / 64
		tMul := time.Now()
		Out := computeOut(invAsqPacked, B, wordsCW, numDataBits)
		polarPhaseMetrics.mulTot += time.Since(tMul)
		// Pack directly to output bytes
		numMsgs := numCW
		out := make([][]byte, numMsgs)
		tPack := time.Now()
		for cw := 0; cw < numMsgs; cw++ {
			w := cw >> 6
			b := uint(cw) & 63
			bts := make([]byte, numDataBits/8)
			for j := 0; j < len(bts); j++ {
				var x byte
				base := j * 8
				if ((Out[base+0][w] >> b) & 1) == 1 {
					x |= 1 << 0
				}
				if ((Out[base+1][w] >> b) & 1) == 1 {
					x |= 1 << 1
				}
				if ((Out[base+2][w] >> b) & 1) == 1 {
					x |= 1 << 2
				}
				if ((Out[base+3][w] >> b) & 1) == 1 {
					x |= 1 << 3
				}
				if ((Out[base+4][w] >> b) & 1) == 1 {
					x |= 1 << 4
				}
				if ((Out[base+5][w] >> b) & 1) == 1 {
					x |= 1 << 5
				}
				if ((Out[base+6][w] >> b) & 1) == 1 {
					x |= 1 << 6
				}
				if ((Out[base+7][w] >> b) & 1) == 1 {
					x |= 1 << 7
				}
				bts[j] = x
			}
			out[cw] = bts
		}
		polarPhaseMetrics.packTot += time.Since(tPack)
		polarPhaseMetrics.totalCW += numCW
		polarPhaseMetrics.batches++
		// metrics: per-batch accounting: 1 cold CW (no inversion time on cache hit), rest warm
		totalDur := time.Since(totalStart)
		polarDecodeMetrics.coldCWs += 1
		// no addition to coldTotal since we reused inverse (invDur=0)
		if numCW > 1 {
			polarDecodeMetrics.warmCWs += (numCW - 1)
			polarDecodeMetrics.warmTotal += totalDur
		}
		return out, nil
	}
	// Row selection: try a fast greedy assignment using (r & j)==j; fall back to packed-basis selection.
	Gcols, infoCols := getInfoColsAndG(n, encodingIndex, numDataBits)
	// Compute known row indices once
	presentRow := make([]bool, N)
	for i := 0; i < N; i++ {
		s := inv[i]
		subset := s / subsetSizeBits
		presentRow[i] = present[subset]
	}
	knownRowIdx := make([]int, 0, N)
	for r := 0; r < N; r++ {
		if presentRow[r] {
			knownRowIdx = append(knownRowIdx, r)
		}
	}
	// Greedy mapping from columns to known rows
	usedRows := make([]int, numDataBits)
	for i := 0; i < numDataBits; i++ {
		usedRows[i] = -1
	}
	usedFlag := make([]bool, len(knownRowIdx))
	for c := 0; c < numDataBits; c++ {
		j := infoCols[c]
		for ridx, r := range knownRowIdx {
			if usedFlag[ridx] {
				continue
			}
			if (r & j) == j {
				usedRows[c] = r
				usedFlag[ridx] = true
				break
			}
		}
	}
	haveAll := true
	for i := 0; i < numDataBits; i++ {
		if usedRows[i] == -1 {
			haveAll = false
			break
		}
	}
	var Asq [][]bool
	if haveAll {
		Asq = make([][]bool, numDataBits)
		for i := 0; i < numDataBits; i++ {
			r := usedRows[i]
			row := make([]bool, numDataBits)
			for c := 0; c < numDataBits; c++ {
				row[c] = Gcols[c][r]
			}
			Asq[i] = row
		}
	} else {
		// Fallback: basis selection via packed columns
		packedCols, _ := getPackedInfoCols(n, encodingIndex, numDataBits)
		wordsK := (numDataBits + 63) / 64
		basisRows := make([][]uint64, 0, numDataBits)
		basisPivot := make([]int, 0, numDataBits)
		usedRows = usedRows[:0]
		getColBit := func(c, r int) bool { w := r >> 6; b := uint(r & 63); return ((packedCols[c][w] >> b) & 1) == 1 }
		for _, r := range knownRowIdx {
			if len(basisRows) >= numDataBits {
				break
			}
			v := make([]uint64, wordsK)
			for c := 0; c < numDataBits; c++ {
				if getColBit(c, r) {
					v[c>>6] |= 1 << uint(c&63)
				}
			}
			for i := 0; i < len(basisRows); i++ {
				pcol := basisPivot[i]
				if ((v[pcol>>6] >> uint(pcol&63)) & 1) == 1 {
					for w := 0; w < wordsK; w++ {
						v[w] ^= basisRows[i][w]
					}
				}
			}
			pivot := -1
			for w := 0; w < wordsK; w++ {
				if v[w] != 0 {
					tz := bits.TrailingZeros64(v[w])
					pivot = (w << 6) + tz
					break
				}
			}
			if pivot == -1 {
				continue
			}
			basisRows = append(basisRows, v)
			basisPivot = append(basisPivot, pivot)
			usedRows = append(usedRows, r)
		}
		if len(usedRows) != numDataBits {
			return nil, errors.New("insufficient rank for erasure recovery")
		}
		Asq = make([][]bool, numDataBits)
		for i := 0; i < numDataBits; i++ {
			r := usedRows[i]
			row := make([]bool, numDataBits)
			for c := 0; c < numDataBits; c++ {
				row[c] = Gcols[c][r]
			}
			Asq[i] = row
		}
	}
	// Measure inversion time separately to attribute to a single cold CW
	invStart := time.Now()
	invAsqPacked, ok := invertBoolMatrixGF2Packed(Asq)
	if !ok {
		return nil, errors.New("polar erasure inversion failed")
	}
	invDur := time.Since(invStart)
	polarPhaseMetrics.invBuilds++
	polarPhaseMetrics.invBuildTot += invDur
	// Cache inverse, used rows, and per-row metadata for warm RHS builds
	// Precompute rowInfo
	subsetBytes := subsetSizeBits / 8
	rowInfo := make([]struct {
		subset, byteOff int
		bitMask         byte
	}, numDataBits)
	for c := 0; c < numDataBits; c++ {
		r := usedRows[c]
		s := inv[r]
		subset := s / subsetSizeBits
		within := s % subsetSizeBits
		rowInfo[c] = struct {
			subset, byteOff int
			bitMask         byte
		}{subset: subset, byteOff: within >> 3, bitMask: 1 << uint(within&7)}
	}
	invCacheMap[struct {
		mask  uint32
		kinfo int
	}{mask: mask, kinfo: numDataBits}] = struct {
		inv         [][]uint64
		usedRows    []int
		subsetBytes int
		rowInfo     []struct {
			subset, byteOff int
			bitMask         byte
		}
	}{inv: invAsqPacked, usedRows: usedRows, subsetBytes: subsetBytes, rowInfo: rowInfo}
	// Build B using precomputed rowInfo (same as warm path)
	// infer num codewords from any present packet
	tBStart := time.Now()
	var pktLen int
	for i := 0; i < K; i++ {
		if present[i] {
			pktLen = len(interleavedPackets[i])
			break
		}
	}
	totalBits := pktLen * 8
	numCW := totalBits / subsetSizeBits
	wordsCW := (numCW + 63) / 64
	B := make([][]uint64, numDataBits)
	for c := 0; c < numDataBits; c++ {
		info := rowInfo[c]
		row := make([]uint64, wordsCW)
		if present[info.subset] {
			pkt := interleavedPackets[info.subset]
			base := info.byteOff
			for cw := 0; cw < numCW; cw++ {
				idx := cw*subsetBytes + base
				if pkt[idx]&info.bitMask != 0 {
					row[cw>>6] |= 1 << uint(cw&63)
				}
			}
		}
		B[c] = row
	}
	polarPhaseMetrics.bBuildTot += time.Since(tBStart)
	polarPhaseMetrics.totalCW += numCW
	polarPhaseMetrics.coldCW += numCW
	polarPhaseMetrics.batches++
	tMul := time.Now()
	Out := make([][]uint64, numDataBits)
	for i := 0; i < numDataBits; i++ {
		acc := make([]uint64, wordsCW)
		for pb := 0; pb < len(invAsqPacked[i]); pb++ {
			m := invAsqPacked[i][pb]
			for m != 0 {
				tz := bits.TrailingZeros64(m)
				col := (pb << 6) + tz
				brow := B[col]
				for w := 0; w < wordsCW; w++ {
					acc[w] ^= brow[w]
				}
				m &= m - 1
			}
		}
		Out[i] = acc
	}
	polarPhaseMetrics.mulTot += time.Since(tMul)
	// Pack directly to output bytes
	numMsgs := numCW
	out := make([][]byte, numMsgs)
	tPack := time.Now()
	for cw := 0; cw < numMsgs; cw++ {
		w := cw >> 6
		b := uint(cw) & 63
		bts := make([]byte, numDataBits/8)
		for j := 0; j < len(bts); j++ {
			var x byte
			base := j * 8
			if ((Out[base+0][w] >> b) & 1) == 1 {
				x |= 1 << 0
			}
			if ((Out[base+1][w] >> b) & 1) == 1 {
				x |= 1 << 1
			}
			if ((Out[base+2][w] >> b) & 1) == 1 {
				x |= 1 << 2
			}
			if ((Out[base+3][w] >> b) & 1) == 1 {
				x |= 1 << 3
			}
			if ((Out[base+4][w] >> b) & 1) == 1 {
				x |= 1 << 4
			}
			if ((Out[base+5][w] >> b) & 1) == 1 {
				x |= 1 << 5
			}
			if ((Out[base+6][w] >> b) & 1) == 1 {
				x |= 1 << 6
			}
			if ((Out[base+7][w] >> b) & 1) == 1 {
				x |= 1 << 7
			}
			bts[j] = x
		}
		out[cw] = bts
	}
	polarPhaseMetrics.packTot += time.Since(tPack)
	// metrics: attribute inversion time to 1 cold CW, rest to warm CWs
	totalDur := time.Since(totalStart)
	if numCW > 0 {
		polarDecodeMetrics.coldTotal += invDur
		polarDecodeMetrics.coldCWs += 1
		// remaining duration counts as warm across the remaining codewords
		polarDecodeMetrics.warmTotal += totalDur - invDur
		if numCW > 1 {
			polarDecodeMetrics.warmCWs += (numCW - 1)
		}
	}
	return out, nil
}

// If map[new_idx] = old_idx, then invMap[old_idx] = new_idx.
func invertMap(forwardMap []int) []int {
	n := len(forwardMap)
	inverseMap := make([]int, n)
	for newIndex, oldIndex := range forwardMap {
		inverseMap[oldIndex] = newIndex
	}
	return inverseMap
}

// DeinterleaveAndReassemble recovers the original codewords from the interleaved packets.
func DeinterleaveAndReassemble(interleavedPackets [][]byte, randomMap []int) (originalCodewords [][]byte, err error) {
	K := len(interleavedPackets)
	if K == 0 {
		return nil, errors.New("input packets cannot be empty")
	}

	// --- Constants must match the encoder ---
	const outputPacketSizeBytes = 1024
	const codewordBytes = 128
	const codewordBits = codewordBytes * 8 // 1024
	numCodewords := K * 8

	// --- 1. Unpack all input packets into bit-level representations ---
	packetsAsBits := make([][]bool, K)
	for i, packet := range interleavedPackets {
		if len(packet) != outputPacketSizeBytes {
			return nil, errors.New("invalid packet size for packet")
		}
		packetBits := make([]bool, outputPacketSizeBytes*8)
		for j, byteVal := range packet {
			for bitOffset := range 8 {
				packetBits[j*8+bitOffset] = (byteVal>>bitOffset)&1 == 1
			}
		}
		packetsAsBits[i] = packetBits
	}

	// --- 2. Reassemble Shuffled Codewords by Gathering Subsets ---
	subsetSizeBits := codewordBits / K
	reassembledShuffledCodewordsBits := make([][]bool, numCodewords)

	// For each codeword we want to rebuild...
	for cwIdx := range numCodewords {
		shuffledCodeword := make([]bool, codewordBits)
		// ...gather its subsets from every packet.
		for subsetIdx := range K {
			// Source: The correct chunk from the packet's bitstream
			sourcePacketBits := packetsAsBits[subsetIdx]
			sourceStartOffset := cwIdx * subsetSizeBits
			subset := sourcePacketBits[sourceStartOffset : sourceStartOffset+subsetSizeBits]

			// Destination: The correct slot in the codeword we are building
			destStartOffset := subsetIdx * subsetSizeBits
			copy(shuffledCodeword[destStartOffset:], subset)
		}
		reassembledShuffledCodewordsBits[cwIdx] = shuffledCodeword
	}

	// --- 3. De-shuffle Bits of Each Codeword and Pack to Bytes ---
	inverseRandomMap := invertMap(randomMap)
	originalCodewords = make([][]byte, numCodewords)
	deShuffledBits := make([]bool, codewordBits)

	for cwIdx, shuffledBits := range reassembledShuffledCodewordsBits {
		// a) De-shuffle using the inverse map
		for i := range codewordBits {
			deShuffledBits[i] = shuffledBits[inverseRandomMap[i]]
		}

		// b) Pack the de-shuffled bits back into a byte slice
		codewordBytesResult := make([]byte, codewordBytes)
		for i := range codewordBytes {
			var packedByte byte
			for bitOffset := range 8 {
				if deShuffledBits[i*8+bitOffset] {
					packedByte |= (1 << bitOffset)
				}
			}
			codewordBytesResult[i] = packedByte
		}
		originalCodewords[cwIdx] = codewordBytesResult
	}

	return originalCodewords, nil
}

// DeinterleaveAndReassembleLLRs reconstructs codeword LLRs directly, treating any missing packet
// (nil or empty slice) as an erasure. Present bits get +/- baseLLR, missing bits get 0.
func DeinterleaveAndReassembleLLRs(interleavedPackets [][]byte, randomMap []int, baseLLR float64) ([][]float64, error) {
	K := len(interleavedPackets)
	if K == 0 {
		return nil, errors.New("input packets cannot be empty")
	}

	const outputPacketSizeBytes = 1024
	const codewordBytes = 128
	const codewordBits = codewordBytes * 8 // 1024
	numCodewords := K * 8

	// Unpack present packets to bit arrays; mark missing ones.
	packetsAsBits := make([][]bool, K)
	present := make([]bool, K)
	for i, packet := range interleavedPackets {
		if len(packet) == 0 {
			present[i] = false
			continue
		}
		if len(packet) != outputPacketSizeBytes {
			return nil, errors.New("invalid packet size for packet")
		}
		present[i] = true
		packetBits := make([]bool, outputPacketSizeBytes*8)
		for j, byteVal := range packet {
			for bitOffset := 0; bitOffset < 8; bitOffset++ {
				packetBits[j*8+bitOffset] = (byteVal>>bitOffset)&1 == 1
			}
		}
		packetsAsBits[i] = packetBits
	}

	// Gather subsets for each codeword, tracking presence mask.
	subsetSizeBits := codewordBits / K
	reassembledShuffledBits := make([][]bool, numCodewords)
	reassembledShuffledMask := make([][]bool, numCodewords)
	for cwIdx := 0; cwIdx < numCodewords; cwIdx++ {
		sbits := make([]bool, codewordBits)
		smask := make([]bool, codewordBits)
		for subsetIdx := 0; subsetIdx < K; subsetIdx++ {
			destStart := subsetIdx * subsetSizeBits
			if present[subsetIdx] {
				srcBits := packetsAsBits[subsetIdx]
				srcStart := cwIdx * subsetSizeBits
				copy(sbits[destStart:destStart+subsetSizeBits], srcBits[srcStart:srcStart+subsetSizeBits])
				for i := 0; i < subsetSizeBits; i++ {
					smask[destStart+i] = true
				}
			} else {
				// missing packet: leave bits default false and mask false
			}
		}
		reassembledShuffledBits[cwIdx] = sbits
		reassembledShuffledMask[cwIdx] = smask
	}

	// De-shuffle and convert to LLRs
	inverseRandomMap := invertMap(randomMap)
	llrs := make([][]float64, numCodewords)
	for cwIdx := 0; cwIdx < numCodewords; cwIdx++ {
		llr := make([]float64, codewordBits)
		for i := 0; i < codewordBits; i++ {
			src := inverseRandomMap[i]
			if reassembledShuffledMask[cwIdx][src] {
				bit := reassembledShuffledBits[cwIdx][src]
				if bit {
					llr[i] = -baseLLR // 1 -> negative
				} else {
					llr[i] = baseLLR // 0 -> positive
				}
			} else {
				llr[i] = 0 // erasure
			}
		}
		llrs[cwIdx] = llr
	}
	return llrs, nil
}

// DeinterleaveAndReassembleKnown returns de-shuffled codeword bits and a mask indicating presence.
func DeinterleaveAndReassembleKnown(interleavedPackets [][]byte, randomMap []int) ([][]bool, [][]bool, error) {
	K := len(interleavedPackets)
	if K == 0 {
		return nil, nil, errors.New("input packets cannot be empty")
	}
	const codewordBits = 1024
	subsetSizeBits := codewordBits / K
	// infer numCodewords from any non-empty packet
	var pktLen int
	for _, p := range interleavedPackets {
		if len(p) > 0 {
			pktLen = len(p)
			break
		}
	}
	if pktLen == 0 {
		return nil, nil, errors.New("all packets missing")
	}
	totalBits := pktLen * 8
	if totalBits%subsetSizeBits != 0 {
		return nil, nil, errors.New("packet size invalid for K")
	}
	numCodewords := totalBits / subsetSizeBits

	// unpack packets
	packetsAsBits := make([][]bool, K)
	present := make([]bool, K)
	for i, packet := range interleavedPackets {
		if len(packet) == 0 {
			continue
		}
		present[i] = true
		bits := make([]bool, len(packet)*8)
		for j, b := range packet {
			for bit := 0; bit < 8; bit++ {
				bits[j*8+bit] = ((b >> bit) & 1) == 1
			}
		}
		packetsAsBits[i] = bits
	}

	// gather shuffled bits and mask per codeword
	shuffledBits := make([][]bool, numCodewords)
	shuffledMask := make([][]bool, numCodewords)
	for cwIdx := 0; cwIdx < numCodewords; cwIdx++ {
		sb := make([]bool, codewordBits)
		sm := make([]bool, codewordBits)
		for subsetIdx := 0; subsetIdx < K; subsetIdx++ {
			destStart := subsetIdx * subsetSizeBits
			if present[subsetIdx] {
				src := packetsAsBits[subsetIdx]
				srcStart := cwIdx * subsetSizeBits
				copy(sb[destStart:destStart+subsetSizeBits], src[srcStart:srcStart+subsetSizeBits])
				for i := 0; i < subsetSizeBits; i++ {
					sm[destStart+i] = true
				}
			}
		}
		shuffledBits[cwIdx] = sb
		shuffledMask[cwIdx] = sm
	}

	// de-shuffle
	inv := invertMap(randomMap)
	bits := make([][]bool, numCodewords)
	masks := make([][]bool, numCodewords)
	for cwIdx := 0; cwIdx < numCodewords; cwIdx++ {
		b := make([]bool, codewordBits)
		m := make([]bool, codewordBits)
		for i := 0; i < codewordBits; i++ {
			src := inv[i]
			b[i] = shuffledBits[cwIdx][src]
			m[i] = shuffledMask[cwIdx][src]
		}
		bits[cwIdx] = b
		masks[cwIdx] = m
	}
	return bits, masks, nil
}

// bitReverseN returns the integer formed by reversing the lower n bits of x.
func bitReverseN(x int, n int) int {
	var r int
	for i := 0; i < n; i++ {
		r = (r << 1) | ((x >> i) & 1)
	}
	return r
}

func DecodeAndRecoverFrames(interleavedPackets [][]byte, randomMap, encodingIndex []int) ([][]byte, error) {
	K := len(interleavedPackets)
	const frameSize = 512
	const polarN = 10
	const numDataBits = 512
	// Recover known codeword bits and presence mask
	cwBits, _, err := DeinterleaveAndReassembleKnown(interleavedPackets, randomMap)
	if err != nil {
		return nil, errors.New("failed to reassemble")
	}
	frozenSet := make(map[int]struct{})
	// Build data set in our decoder's u-domain by bit-reversing indices.
	isDataIndex := make(map[int]struct{}, numDataBits)
	for i := range numDataBits {
		isDataIndex[bitReverseN(encodingIndex[i], polarN)] = struct{}{}
	}
	for i := range 1 << polarN {
		if _, isData := isDataIndex[i]; !isData {
			frozenSet[i] = struct{}{}
		}
	}
	// Fast path: if no erasure (all bits known), use involutory transform to invert F^{\otimes n}
	// Fast path: no packet loss
	dropIdx := -1
	for i, p := range interleavedPackets {
		if len(p) == 0 {
			dropIdx = i
			break
		}
	}
	allKnown := dropIdx == -1
	if allKnown {
		allDataBits := make([]int, 0, K*frameSize*8)
		N := 1 << polarN
		dataIdx := make([]int, numDataBits)
		for i := 0; i < numDataBits; i++ {
			dataIdx[i] = bitReverseN(encodingIndex[i], polarN)
		}
		u := make([]bool, N)
		for cw := 0; cw < len(cwBits); cw++ {
			// copy x
			copy(u, cwBits[cw])
			// apply F^{\otimes n} again (self-inverse) to get u
			for s := 0; s < polarN; s++ {
				block := 1 << (s + 1)
				half := 1 << s
				for start := 0; start < N; start += block {
					for k := 0; k < half; k++ {
						i1 := start + k
						i2 := i1 + half
						u[i1] = u[i1] != u[i2]
					}
				}
			}
			for i := 0; i < numDataBits; i++ {
				if u[dataIdx[i]] {
					allDataBits = append(allDataBits, 1)
				} else {
					allDataBits = append(allDataBits, 0)
				}
			}
		}
		numFrames := len(allDataBits) / (frameSize * 8)
		recoveredFrames := make([][]byte, numFrames)
		bitCounter := 0
		for i := range numFrames {
			frameBytes := make([]byte, frameSize)
			for j := range frameSize {
				var b byte
				for k := 0; k < 8; k++ {
					if allDataBits[bitCounter] == 1 {
						b |= 1 << k
					}
					bitCounter++
				}
				frameBytes[j] = b
			}
			recoveredFrames[i] = frameBytes
		}
		return recoveredFrames, nil
	}

	// Erasure path: Build only the K=512 info columns using butterfly
	Gcols, infoCols := getInfoColsAndG(polarN, encodingIndex, numDataBits)
	N := 1 << polarN

	// Build known rows from randomMap using dropIdx
	subsetSizeBits := N / K
	presentRow := make([]bool, N)
	for i := 0; i < N; i++ {
		presentRow[i] = true
	}
	if dropIdx >= 0 {
		start := dropIdx * subsetSizeBits
		for pos := start; pos < start+subsetSizeBits; pos++ {
			presentRow[randomMap[pos]] = false
		}
	}
	knownRowIdx := make([]int, 0, N)
	for r := 0; r < N; r++ {
		if presentRow[r] {
			knownRowIdx = append(knownRowIdx, r)
		}
	}

	// Use inverse cache indexed by loss mask and info size if available
	var mask uint32
	if dropIdx >= 0 {
		mask = 1 << uint(dropIdx)
	}
	if dropIdx >= 0 {
		if e, ok := invCacheMap[struct {
			mask  uint32
			kinfo int
		}{mask: mask, kinfo: numDataBits}]; ok {
			invAsqPacked := e.inv
			usedRows := e.usedRows
			// Batch solve using cached inverse
			numCW := len(cwBits)
			wordsCW := (numCW + 63) / 64
			B := make([][]uint64, numDataBits)
			for c := 0; c < numDataBits; c++ {
				row := make([]uint64, wordsCW)
				for cw := 0; cw < numCW; cw++ {
					if cwBits[cw][usedRows[c]] {
						row[cw>>6] |= 1 << (uint(cw) & 63)
					}
				}
				B[c] = row
			}
			Out := make([][]uint64, numDataBits)
			for i := 0; i < numDataBits; i++ {
				acc := make([]uint64, wordsCW)
				for pb := 0; pb < len(invAsqPacked[i]); pb++ {
					m := invAsqPacked[i][pb]
					for m != 0 {
						tz := bits.TrailingZeros64(m)
						col := (pb << 6) + tz
						brow := B[col]
						for w := 0; w < wordsCW; w++ {
							acc[w] ^= brow[w]
						}
						m &= m - 1
					}
				}
				Out[i] = acc
			}
			allDataBits := make([]int, 0, K*frameSize*8)
			for cw := 0; cw < numCW; cw++ {
				w := cw >> 6
				b := uint(cw) & 63
				for i := 0; i < numDataBits; i++ {
					if ((Out[i][w] >> b) & 1) == 1 {
						allDataBits = append(allDataBits, 1)
					} else {
						allDataBits = append(allDataBits, 0)
					}
				}
			}
			// Pack frames
			numFrames := len(allDataBits) / (frameSize * 8)
			recoveredFrames := make([][]byte, numFrames)
			bitCounter := 0
			for i := range numFrames {
				frameBytes := make([]byte, frameSize)
				for j := range frameSize {
					var b byte
					for k := 0; k < 8; k++ {
						if allDataBits[bitCounter] == 1 {
							b |= 1 << k
						}
						bitCounter++
					}
					frameBytes[j] = b
				}
				recoveredFrames[i] = frameBytes
			}
			return recoveredFrames, nil
		}
	}
	// Assemble A rows once
	rowsA := make([][]bool, 0, len(knownRowIdx))
	for _, r := range knownRowIdx {
		arow := make([]bool, numDataBits)
		for c := 0; c < numDataBits; c++ {
			arow[c] = Gcols[c][r]
		}
		rowsA = append(rowsA, arow)
	}
	// Prefer a greedy per-column pivot row assignment using (r & j)==j to avoid rank issues
	used := make([]bool, len(knownRowIdx))
	colRow := make([]int, numDataBits)
	for c := 0; c < numDataBits; c++ {
		colRow[c] = -1
	}
	for c := 0; c < numDataBits; c++ {
		j := infoCols[c]
		for ridx, r := range knownRowIdx {
			if used[ridx] {
				continue
			}
			if (r & j) == j {
				colRow[c] = ridx
				used[ridx] = true
				break
			}
		}
	}
	haveAll := true
	for c := 0; c < numDataBits; c++ {
		if colRow[c] == -1 {
			haveAll = false
			break
		}
	}
	var Asq [][]bool
	if haveAll {
		Asq = make([][]bool, numDataBits)
		for i := 0; i < numDataBits; i++ {
			Asq[i] = append([]bool(nil), rowsA[colRow[i]]...)
		}
	} else {
		// Fallback: choose K independent rows via elimination on all known rows
		pivotRows, ok := selectPivotRows(rowsA, numDataBits)
		if !ok {
			return nil, errors.New("polar erasure rank deficiency")
		}
		Asq = make([][]bool, numDataBits)
		for i := 0; i < numDataBits; i++ {
			Asq[i] = append([]bool(nil), rowsA[pivotRows[i]]...)
		}
	}
	invAsqPacked, ok := invertBoolMatrixGF2Packed(Asq)
	if !ok {
		return nil, errors.New("polar erasure inversion failed")
	}
	// Cache inverse for this mask
	if dropIdx >= 0 {
		usedRows := make([]int, numDataBits)
		if haveAll {
			for i := 0; i < numDataBits; i++ {
				usedRows[i] = knownRowIdx[colRow[i]]
			}
		} else {
			pr, _ := selectPivotRows(rowsA, numDataBits)
			for i := 0; i < numDataBits; i++ {
				usedRows[i] = knownRowIdx[pr[i]]
			}
		}
		// Precompute rowInfo metadata for warm RHS builds
		subsetBytes := subsetSizeBits / 8
		inv := invertMap(randomMap)
		rowInfo := make([]struct {
			subset, byteOff int
			bitMask         byte
		}, numDataBits)
		for c := 0; c < numDataBits; c++ {
			r := usedRows[c]
			s := inv[r]
			subset := s / subsetSizeBits
			within := s % subsetSizeBits
			rowInfo[c] = struct {
				subset, byteOff int
				bitMask         byte
			}{subset: subset, byteOff: within >> 3, bitMask: 1 << uint(within&7)}
		}
		invCacheMap[struct {
			mask  uint32
			kinfo int
		}{mask: mask, kinfo: numDataBits}] = struct {
			inv         [][]uint64
			usedRows    []int
			subsetBytes int
			rowInfo     []struct {
				subset, byteOff int
				bitMask         byte
			}
		}{inv: invAsqPacked, usedRows: usedRows, subsetBytes: subsetBytes, rowInfo: rowInfo}
	}

	// Determine which knownRowIdx rows were used in Asq
	usedRows := make([]int, numDataBits)
	if haveAll {
		for i := 0; i < numDataBits; i++ {
			usedRows[i] = knownRowIdx[colRow[i]]
		}
	} else {
		// Recompute pivot rows used by selectPivotRows over rowsA to map back to knownRowIdx
		// Since Asq was constructed from rowsA[pivotRows[i]], recreate that mapping
		pr, _ := selectPivotRows(rowsA, numDataBits)
		for i := 0; i < numDataBits; i++ {
			usedRows[i] = knownRowIdx[pr[i]]
		}
	}

	// Batch solve for all codewords at once: Out = invAsq * B over GF(2), packed across codewords
	numCW := len(cwBits)
	wordsCW := (numCW + 63) / 64
	// Build B: K rows x wordsCW words, where B[c][w] holds cw-bits for column c
	B := make([][]uint64, numDataBits)
	for c := 0; c < numDataBits; c++ {
		row := make([]uint64, wordsCW)
		for cw := 0; cw < numCW; cw++ {
			if cwBits[cw][usedRows[c]] {
				row[cw>>6] |= 1 << (uint(cw) & 63)
			}
		}
		B[c] = row
	}
	// Out = invAsqPacked (KxK) * B (KxW)
	Out := make([][]uint64, numDataBits)
	for i := 0; i < numDataBits; i++ {
		acc := make([]uint64, wordsCW)
		for pb := 0; pb < len(invAsqPacked[i]); pb++ {
			m := invAsqPacked[i][pb]
			for m != 0 {
				tz := bits.TrailingZeros64(m)
				col := (pb << 6) + tz
				brow := B[col]
				for w := 0; w < wordsCW; w++ {
					acc[w] ^= brow[w]
				}
				m &= m - 1
			}
		}
		Out[i] = acc
	}
	// Extract per-codeword info bits
	allDataBits := make([]int, 0, K*frameSize*8)
	for cw := 0; cw < numCW; cw++ {
		w := cw >> 6
		b := uint(cw) & 63
		for i := 0; i < numDataBits; i++ {
			if ((Out[i][w] >> b) & 1) == 1 {
				allDataBits = append(allDataBits, 1)
			} else {
				allDataBits = append(allDataBits, 0)
			}
		}
	}
	numFrames := len(allDataBits) / (frameSize * 8)
	recoveredFrames := make([][]byte, numFrames)
	bitCounter := 0
	for i := range numFrames {
		frameBytes := make([]byte, frameSize)
		for j := range frameSize {
			var packedByte byte
			for k := range 8 {
				if allDataBits[bitCounter] == 1 {
					packedByte |= (1 << k)
				}
				bitCounter++
			}
			frameBytes[j] = packedByte
		}
		recoveredFrames[i] = frameBytes
	}
	return recoveredFrames, nil
}
