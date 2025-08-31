package fec

// Simple GF(256) arithmetic using log/antilog tables with primitive polynomial 0x11d.

var (
	gfExp    [512]byte
	gfLog    [256]byte
	gfInited bool
	// compatibility tables for existing code
	expTable [512]byte
	logTable [256]byte
)

func gf256Init() {
	if gfInited {
		return
	}
	// generator = 0x02, primitive polynomial = 0x11d
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[byte(x)] = byte(i)
		x <<= 1
		if (x & 0x100) != 0 { // carry out from bit 8
			x ^= 0x11d // reduce by 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
	gfInited = true
	// fill legacy tables
	copy(expTable[:], gfExp[:])
	copy(logTable[:], gfLog[:])
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	if !gfInited {
		gf256Init()
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	if !gfInited {
		gf256Init()
	}
	return gfExp[255-int(gfLog[a])]
}

// no gfAdd/gfDiv needed; use XOR and gfMul+gfInv as required

// alphaPow returns generator^e, with e mod 255.
func alphaPow(e int) byte {
	if !gfInited {
		gf256Init()
	}
	e %= 255
	if e < 0 {
		e += 255
	}
	if e == 0 {
		return 1
	}
	return gfExp[e]
}

// gfMulBytes multiplies src by scalar a and xors into dst: dst ^= a*src
func gfMulBytes(dst, src []byte, a byte) {
	if a == 0 {
		return
	}
	if a == 1 {
		xorBytes(dst, src)
		return
	}
	for i := 0; i < len(dst) && i < len(src); i++ {
		dst[i] ^= gfMul(a, src[i])
	}
}

// Legacy wrappers
func gf256Mul(a, b byte) byte { return gfMul(a, b) }
func gf256Inv(a byte) byte    { return gfInv(a) }

func gf256InvertMatrix(A [][]byte) ([][]byte, bool) {
	n := len(A)
	aug := make([][]byte, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]byte, n*2)
		copy(aug[i][:n], A[i])
		aug[i][n+i] = 1
	}
	row := 0
	for col := 0; col < n && row < n; col++ {
		pivot := -1
		for r := row; r < n; r++ {
			if aug[r][col] != 0 {
				pivot = r
				break
			}
		}
		if pivot == -1 {
			continue
		}
		aug[row], aug[pivot] = aug[pivot], aug[row]
		inv := gf256Inv(aug[row][col])
		for j := 0; j < 2*n; j++ {
			aug[row][j] = gf256Mul(aug[row][j], inv)
		}
		for r := 0; r < n; r++ {
			if r == row {
				continue
			}
			factor := aug[r][col]
			if factor == 0 {
				continue
			}
			for j := 0; j < 2*n; j++ {
				aug[r][j] ^= gf256Mul(aug[row][j], factor)
			}
		}
		row++
	}
	if row < n {
		return nil, false
	}
	invA := make([][]byte, n)
	for i := 0; i < n; i++ {
		invA[i] = make([]byte, n)
		copy(invA[i], aug[i][n:])
	}
	return invA, true
}
