package fec

import (
	crand "crypto/rand"
	"math/rand"
)

// EncodeRLC generates R parity packets for K sources using GF(256) random linear combination.
// field may be "gf256" or "gf2". For gf2, coefficients are bits and only XOR is used.
// Returns parity packets, each stored as Packet with Index=K+j and coefficient header included.
func EncodeRLC(src [][]byte, K, R int, field string) []Packet {
	L := 0
	if len(src) > 0 {
		L = len(src[0])
	}
	out := make([]Packet, R)
	// choose coefficient generator
	newCoeff := func() []byte {
		c := make([]byte, K)
		switch field {
		case "gf2":
			// random bits (but we store as bytes 0/1)
			// ensure not all-zero to avoid trivial zero packet
			for {
				var b [32]byte
				crand.Read(b[:])
				for i := 0; i < K; i++ {
					if ((b[i/8] >> uint(i%8)) & 1) == 1 {
						c[i] = 1
					} else {
						c[i] = 0
					}
				}
				nz := false
				for i := 0; i < K; i++ {
					if c[i] != 0 {
						nz = true
						break
					}
				}
				if nz {
					break
				}
			}
		default:
			// gf256
			// draw non-zero coefficients to reduce rank deficiency
			for i := 0; i < K; i++ {
				for c[i] == 0 {
					x := make([]byte, 1)
					crand.Read(x)
					c[i] = x[0]
				}
			}
		}
		return c
	}
	for j := 0; j < R; j++ {
		coeff := newCoeff()
		y := make([]byte, L)
		if field == "gf2" {
			for i := 0; i < K; i++ {
				if coeff[i]&1 == 1 {
					xorBytes(y, src[i])
				}
			}
		} else {
			for i := 0; i < K; i++ {
				gfMulBytes(y, src[i], coeff[i])
			}
		}
		// prepend coeff header (K bytes) to data for decode
		pkt := make([]byte, K+L)
		copy(pkt, coeff)
		copy(pkt[K:], y)
		out[j] = Packet{Index: K + j, Data: pkt}
	}
	return out
}

// DecodeRLC recovers K sources from m>=K packets. Packets with Index<K are systematic with implicit unit vector.
// Parity packets include K-byte coefficient header at the front.
func DecodeRLC(recv []Packet, K int, field string) ([][]byte, bool) {
	if len(recv) < K {
		return nil, false
	}
	// Determine symbol length Lsym consistently:
	// - for systematic packets (Index < K): Lsym = len(Data)
	// - for parity packets (Index >= K): Lsym = len(Data) - K (coeff header)
	Lsym := 0
	for _, p := range recv {
		if p.Data == nil {
			continue
		}
		if p.Index < K {
			if l := len(p.Data); l > 0 {
				Lsym = l
				break
			}
		}
	}
	if Lsym == 0 {
		for _, p := range recv {
			if p.Data == nil || len(p.Data) < K {
				continue
			}
			if l := len(p.Data) - K; l > 0 {
				Lsym = l
				break
			}
		}
	}
	if Lsym == 0 {
		return nil, false
	}
	// Build rows (vec, data)
	type row struct {
		vec  []byte
		data []byte
	}
	rows := make([]row, 0, len(recv))
	for _, p := range recv {
		if p.Data == nil {
			continue
		}
		if p.Index < K {
			// systematic: implicit unit vector, data length must be Lsym
			if len(p.Data) < Lsym {
				continue
			}
			v := make([]byte, K)
			v[p.Index] = 1
			d := make([]byte, Lsym)
			copy(d, p.Data[:Lsym])
			rows = append(rows, row{v, d})
		} else {
			// parity: first K bytes are coeff header, followed by Lsym data
			if len(p.Data) < K+Lsym {
				continue
			}
			v := make([]byte, K)
			copy(v, p.Data[:K])
			d := make([]byte, Lsym)
			copy(d, p.Data[K:K+Lsym])
			rows = append(rows, row{v, d})
		}
	}
	if len(rows) < K {
		return nil, false
	}
	// Gaussian elimination in chosen field
	m := len(rows)
	r := 0
	for c := 0; c < K && r < m; c++ {
		pr := -1
		for i := r; i < m; i++ {
			if rows[i].vec[c] != 0 {
				pr = i
				break
			}
		}
		if pr == -1 {
			continue
		}
		rows[r], rows[pr] = rows[pr], rows[r]
		// normalize pivot row to make pivot 1 in gf256; gf2 already 1
		if field != "gf2" {
			inv := gfInv(rows[r].vec[c])
			for j := 0; j < K; j++ {
				rows[r].vec[j] = gfMul(rows[r].vec[j], inv)
			}
			// scale data: data = inv * data
			for j := 0; j < len(rows[r].data); j++ {
				rows[r].data[j] = gfMul(rows[r].data[j], inv)
			}
		}
		// eliminate others
		for i := 0; i < m; i++ {
			if i == r {
				continue
			}
			a := rows[i].vec[c]
			if a == 0 {
				continue
			}
			if field == "gf2" {
				for j := 0; j < K; j++ {
					rows[i].vec[j] ^= rows[r].vec[j]
				}
				xorBytes(rows[i].data, rows[r].data)
			} else {
				for j := 0; j < K; j++ {
					rows[i].vec[j] = rows[i].vec[j] ^ gfMul(a, rows[r].vec[j])
				}
				// data_i -= a * data_r  => in GF(2^8), subtraction is XOR, so: data_i ^= a * data_r
				tmp := make([]byte, len(rows[r].data))
				copy(tmp, rows[r].data)
				for j := 0; j < len(tmp); j++ {
					tmp[j] = gfMul(a, tmp[j])
				}
				xorBytes(rows[i].data, tmp)
			}
		}
		r++
	}
	if r < K {
		return nil, false
	}
	// solutions are rows with pivot at c = i
	out := make([][]byte, K)
	for i := 0; i < K; i++ {
		// find row with vec = e_i
		found := -1
		for j := 0; j < m; j++ {
			ok := true
			for c := 0; c < K; c++ {
				want := byte(0)
				if c == i {
					want = 1
				}
				if rows[j].vec[c] != want {
					ok = false
					break
				}
			}
			if ok {
				found = j
				break
			}
		}
		if found == -1 {
			return nil, false
		}
		out[i] = rows[found].data
	}
	return out, true
}

// deterministic coefficient RNG for tests if needed
var _ = rand.New
