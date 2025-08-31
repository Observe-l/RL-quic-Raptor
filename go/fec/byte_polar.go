package fec

import (
	"errors"
)

// BytePolarEncodePacket encodes a K_bytes-length source into a 1024-byte codeword (non-systematic),
// using 8 bit-planes and the provided reliability sequence (encodingIndex). K_bytes must be 512.
// N is fixed at 1024 for now (n=10).
func BytePolarEncodePacket(src []byte, encodingIndex []int, Kbytes int) ([]byte, error) {
	if Kbytes <= 0 || Kbytes%8 != 0 {
		return nil, errors.New("Kbytes must be positive and a multiple of 8")
	}
	if len(src) != Kbytes {
		return nil, errors.New("src length must equal Kbytes")
	}
	// Build 8 plane messages of length Kbytes bits = Kbytes/8 bytes each.
	planeMsgBytes := Kbytes / 8
	n := 10
	// Output codeword (1024 bytes), to be filled bitwise from plane encodings.
	out := make([]byte, 1024)
	// For each bit-plane, extract plane message then encode via EncodePolarGN (length=64 bytes when Kbytes=512).
	for b := 0; b < 8; b++ {
		mb := make([]byte, planeMsgBytes)
		// pack bit-plane b from src into mb: mb[i] bit k equals bit b of src[8*i + k]
		for i := 0; i < planeMsgBytes; i++ {
			var v byte
			base := i * 8
			for k := 0; k < 8; k++ {
				if ((src[base+k] >> uint(b)) & 1) == 1 {
					v |= 1 << uint(k)
				}
			}
			mb[i] = v
		}
		cw, err := EncodePolarGN(mb, n, encodingIndex)
		if err != nil {
			return nil, err
		}
		if len(cw) != 1024/8 {
			return nil, errors.New("unexpected codeword size")
		}
		// Scatter plane bits into out bytes
		for j := 0; j < 1024; j++ {
			bit := (cw[j>>3] >> uint(j&7)) & 1
			if bit == 1 {
				out[j] |= 1 << uint(b)
			}
		}
	}
	return out, nil
}

// BytePolarDecodePacket decodes Kbytes source from a 1024-byte codeword with a known-byte mask.
// Returns ok=false if rank is insufficient.
func BytePolarDecodePacket(enc []byte, mask []bool, encodingIndex []int, Kbytes int) ([]byte, bool, error) {
	if len(enc) != 1024 || len(mask) != 1024 {
		return nil, false, errors.New("enc/mask must be length 1024")
	}
	n := 10
	// Precompute G columns and info indices for Kbytes info bits per plane.
	Gcols, infoCols := getInfoColsAndG(n, encodingIndex, Kbytes)
	// Determine known row indices S
	knownRowIdx := make([]int, 0, 1024)
	for r := 0; r < 1024; r++ {
		if mask[r] {
			knownRowIdx = append(knownRowIdx, r)
		}
	}
	if len(knownRowIdx) < Kbytes {
		return nil, false, nil // insufficient equations
	}
	// Build rowsA as Kbytes-length boolean rows for each known r
	rowsA := make([][]bool, len(knownRowIdx))
	for i, r := range knownRowIdx {
		row := make([]bool, Kbytes)
		for c := 0; c < Kbytes; c++ {
			row[c] = Gcols[c][r]
		}
		rowsA[i] = row
	}
	// Select K independent rows
	pivots, ok := selectPivotRows(rowsA, Kbytes)
	if !ok {
		return nil, false, nil
	}
	// Build Asq and invert
	Asq := make([][]bool, Kbytes)
	usedRows := make([]int, Kbytes)
	for i := 0; i < Kbytes; i++ {
		idx := pivots[i]
		Asq[i] = append([]bool(nil), rowsA[idx]...)
		usedRows[i] = knownRowIdx[idx]
	}
	inv, ok := invertBoolMatrixGF2(Asq)
	if !ok {
		return nil, false, nil
	}
	// Recover plane messages and assemble bytes
	out := make([]byte, Kbytes)
	// For each plane, build y (length Kbytes) from enc bits at usedRows, solve uA = inv * y, then set bits in out bytes.
	for b := 0; b < 8; b++ {
		y := make([]bool, Kbytes)
		for i := 0; i < Kbytes; i++ {
			r := usedRows[i]
			bit := (enc[r] >> uint(b)) & 1
			y[i] = (bit == 1)
		}
		uA := matVecGF2(inv, y)
		// write plane bits into out bytes: for byte i, bit b = uA[i]
		for i := 0; i < Kbytes; i++ {
			if uA[i] {
				out[i] |= 1 << uint(b)
			}
		}
	}
	// Map infoCols back to byte order? Here, getInfoColsAndG returns infoCols which are bit-reversed indices of reliability sequence.
	// We populated u according to the order of infoCols; the first Kbytes entries correspond to src[0..Kbytes-1] in our encode routine.
	// Thus out already matches original byte order.
	_ = infoCols // kept for symmetry; not needed for reconstruction order here.
	return out, true, nil
}
