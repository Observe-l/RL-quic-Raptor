package fec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
)

// PacketPolarOfflineEntry holds one epsilon's configuration for packet-level Polar.
type PacketPolarOfflineEntry struct {
	Epsilon float64  `json:"epsilon"`
	A       []int    `json:"A"`
	Ac      []int    `json:"Ac"`
	RowsHex []string `json:"rowsHex"` // each parity row serialized as hex(little-endian uint64 words)
	CRC32   uint32   `json:"crc32"`
	SHA256  string   `json:"sha256"`
}

// PacketPolarOfflineTable is the top-level offline table for a fixed (N,K).
type PacketPolarOfflineTable struct {
	Version     int                       `json:"version"`
	N           int                       `json:"N"`
	K           int                       `json:"K"`
	R           int                       `json:"R"`
	WordsPerRow int                       `json:"wordsPerRow"`
	MaxLenHint  int                       `json:"maxLenHint"` // optional; decoding can supply its own L
	Entries     []PacketPolarOfflineEntry `json:"entries"`
}

// Serialize Gpar rows to hex strings.
func serializeGparRows(rows [][]uint64, wordsPerRow int) (rowsHex []string, crc uint32, sha string) {
	h := crc32.NewIEEE()
	sh := sha256.New()
	buf := make([]byte, wordsPerRow*8)
	rowsHex = make([]string, len(rows))
	for i := range rows {
		// fill buf
		off := 0
		for w := 0; w < wordsPerRow; w++ {
			v := rows[i][w]
			// little-endian
			buf[off+0] = byte(v)
			buf[off+1] = byte(v >> 8)
			buf[off+2] = byte(v >> 16)
			buf[off+3] = byte(v >> 24)
			buf[off+4] = byte(v >> 32)
			buf[off+5] = byte(v >> 40)
			buf[off+6] = byte(v >> 48)
			buf[off+7] = byte(v >> 56)
			off += 8
		}
		h.Write(buf)
		sh.Write(buf)
		rowsHex[i] = hex.EncodeToString(buf)
	}
	return rowsHex, h.Sum32(), hex.EncodeToString(sh.Sum(nil))
}

// Parse hex strings back into [][]uint64.
func parseGparRows(rowsHex []string, wordsPerRow int) ([][]uint64, error) {
	rows := make([][]uint64, len(rowsHex))
	for i, hx := range rowsHex {
		b, err := hex.DecodeString(hx)
		if err != nil {
			return nil, fmt.Errorf("decode hex row %d: %w", i, err)
		}
		if len(b) != wordsPerRow*8 {
			return nil, fmt.Errorf("row %d: expected %d bytes, got %d", i, wordsPerRow*8, len(b))
		}
		row := make([]uint64, wordsPerRow)
		off := 0
		for w := 0; w < wordsPerRow; w++ {
			var v uint64
			v |= uint64(b[off+0])
			v |= uint64(b[off+1]) << 8
			v |= uint64(b[off+2]) << 16
			v |= uint64(b[off+3]) << 24
			v |= uint64(b[off+4]) << 32
			v |= uint64(b[off+5]) << 40
			v |= uint64(b[off+6]) << 48
			v |= uint64(b[off+7]) << 56
			row[w] = v
			off += 8
		}
		rows[i] = row
	}
	return rows, nil
}

// SavePacketPolarTable writes the table to a JSON file.
func SavePacketPolarTable(path string, t *PacketPolarOfflineTable) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(t)
}

// LoadPacketPolarTable reads a JSON table.
func LoadPacketPolarTable(path string) (*PacketPolarOfflineTable, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t PacketPolarOfflineTable
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, err
	}
	// basic sanity
	if t.N <= 0 || t.K <= 0 || t.K >= t.N || t.R != t.N-t.K {
		return nil, errors.New("invalid table header")
	}
	if t.WordsPerRow != (t.K+63)/64 {
		return nil, errors.New("mismatched wordsPerRow vs K")
	}
	return &t, nil
}

// Build params for the epsilon closest to reqEps (exact match preferred).
func NewPacketPolarParamsFromTable(tbl *PacketPolarOfflineTable, reqEps float64, maxLen int) (*PacketPolarParams, error) {
	if tbl == nil {
		return nil, errors.New("nil table")
	}
	// pick best entry
	best := -1
	bestDiff := 1e9
	for i, e := range tbl.Entries {
		d := e.Epsilon - reqEps
		if d < 0 {
			d = -d
		}
		if d < bestDiff {
			best = i
			bestDiff = d
		}
		if d == 0 {
			break
		}
	}
	if best < 0 {
		return nil, errors.New("no entries in table")
	}
	e := tbl.Entries[best]
	gpar, err := parseGparRows(e.RowsHex, tbl.WordsPerRow)
	if err != nil {
		return nil, err
	}
	// optional checksum verification
	rowsHex, crc, sha := serializeGparRows(gpar, tbl.WordsPerRow)
	_ = rowsHex // not used; just recomputed
	if crc != e.CRC32 || sha != e.SHA256 {
		return nil, errors.New("gpar checksum mismatch in table")
	}
	p := &PacketPolarParams{
		N: tbl.N, K: tbl.K, Epsilon: e.Epsilon, MaxLen: maxLen,
		n: 0, R: tbl.R, A: append([]int(nil), e.A...), Ac: append([]int(nil), e.Ac...), Gpar: gpar,
	}
	// fill n
	n := 0
	for (1 << n) < tbl.N {
		n++
	}
	p.n = n
	return p, nil
}
