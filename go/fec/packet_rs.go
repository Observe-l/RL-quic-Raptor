package fec

import "errors"

// EncodeRS generates parity packets for systematic RS over GF(256) using Vandermonde construction.
func EncodeRS(src [][]byte, K, R int) ([]Packet, error) {
	if K <= 0 || R < 0 {
		return nil, errors.New("bad K,R")
	}
	if K+R > 255 {
		return nil, errors.New("RS over GF(256) requires N<=255")
	}
	L := 0
	if len(src) > 0 {
		L = len(src[0])
	}
	// Build Vsys and its inverse
	Vsys := make([][]byte, K)
	for i := 0; i < K; i++ {
		Vsys[i] = make([]byte, K)
		x := alphaPow(i)
		pow := byte(1)
		for j := 0; j < K; j++ {
			Vsys[i][j] = pow
			pow = gfMul(pow, x)
		}
	}
	invV, ok := gf256InvertMatrix(Vsys)
	if !ok {
		return nil, errors.New("vsys not invertible")
	}
	out := make([]Packet, R)
	for j := 0; j < R; j++ {
		// Parity at x = alpha^(K+j)
		x := alphaPow(K + j)
		rowV := make([]byte, K)
		pow := byte(1)
		for c := 0; c < K; c++ {
			rowV[c] = pow
			pow = gfMul(pow, x)
		}
		// Compute rowP = rowV * invV
		rowP := make([]byte, K)
		for k := 0; k < K; k++ {
			var acc byte
			for t := 0; t < K; t++ {
				acc ^= gfMul(rowV[t], invV[t][k])
			}
			rowP[k] = acc
		}
		y := make([]byte, L)
		for k := 0; k < K; k++ {
			gfMulBytes(y, src[k], rowP[k])
		}
		out[j] = Packet{Index: K + j, Data: y}
	}
	return out, nil
}

// DecodeRS solves for source packets from any K received packets.
func DecodeRS(recv []Packet, K, R int) ([][]byte, bool) {
	if len(recv) < K {
		return nil, false
	}
	if K+R > 255 {
		return nil, false
	}
	// Determine L
	L := -1
	for _, p := range recv {
		if p.Data != nil {
			L = len(p.Data)
			break
		}
	}
	if L <= 0 {
		return nil, false
	}
	// Precompute inv(Vsys)
	Vsys := make([][]byte, K)
	for i := 0; i < K; i++ {
		Vsys[i] = make([]byte, K)
		x := alphaPow(i)
		pow := byte(1)
		for j := 0; j < K; j++ {
			Vsys[i][j] = pow
			pow = gfMul(pow, x)
		}
	}
	invV, ok := gf256InvertMatrix(Vsys)
	if !ok {
		return nil, false
	}
	// Build rows
	type row struct {
		vec  []byte
		data []byte
	}
	rows := make([]row, 0, len(recv))
	for _, p := range recv {
		if p.Index < K {
			v := make([]byte, K)
			v[p.Index] = 1
			d := make([]byte, L)
			copy(d, p.Data)
			rows = append(rows, row{v, d})
		} else {
			j := p.Index - K
			if j < 0 || j >= R {
				continue
			}
			x := alphaPow(K + j)
			rowV := make([]byte, K)
			pow := byte(1)
			for c := 0; c < K; c++ {
				rowV[c] = pow
				pow = gfMul(pow, x)
			}
			v := make([]byte, K)
			for k := 0; k < K; k++ {
				var acc byte
				for t := 0; t < K; t++ {
					acc ^= gfMul(rowV[t], invV[t][k])
				}
				v[k] = acc
			}
			d := make([]byte, L)
			copy(d, p.Data)
			rows = append(rows, row{v, d})
		}
		if len(rows) == K {
			break
		}
	}
	if len(rows) < K {
		return nil, false
	}
	// Gaussian elimination over GF(256)
	for c, r := 0, 0; c < K && r < K; c++ {
		pr := -1
		for i := r; i < K; i++ {
			if rows[i].vec[c] != 0 {
				pr = i
				break
			}
		}
		if pr == -1 {
			continue
		}
		rows[r], rows[pr] = rows[pr], rows[r]
		inv := gfInv(rows[r].vec[c])
		for j := 0; j < K; j++ {
			rows[r].vec[j] = gfMul(rows[r].vec[j], inv)
		}
		for j := 0; j < L; j++ {
			rows[r].data[j] = gfMul(rows[r].data[j], inv)
		}
		for i := 0; i < K; i++ {
			if i == r {
				continue
			}
			a := rows[i].vec[c]
			if a == 0 {
				continue
			}
			for j := 0; j < K; j++ {
				rows[i].vec[j] ^= gfMul(a, rows[r].vec[j])
			}
			for j := 0; j < L; j++ {
				rows[i].data[j] ^= gfMul(a, rows[r].data[j])
			}
		}
		r++
	}
	out := make([][]byte, K)
	for i := 0; i < K; i++ {
		found := -1
		for j := 0; j < K; j++ {
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
