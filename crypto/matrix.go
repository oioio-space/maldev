package crypto

import (
	"crypto/rand"
	"fmt"
)

// NewMatrixKey generates a random n×n matrix invertible over GF(2^8) (mod 256).
// n must be in [2, 4]. Returns the key matrix and its mod-256 inverse.
//
// Invertibility requires gcd(det(key), 256) == 1, which means det must be odd.
// The function retries until this condition is met (typically < 10 attempts).
func NewMatrixKey(n int) (key [][]byte, inverse [][]byte, err error) {
	if n < 2 || n > 4 {
		return nil, nil, fmt.Errorf("matrix: n must be 2, 3, or 4; got %d", n)
	}
	buf := make([]byte, n*n)
	m := make([][]byte, n)
	for i := range m {
		m[i] = make([]byte, n)
	}
	for attempt := 0; attempt < 1000; attempt++ {
		if _, err = rand.Read(buf); err != nil {
			return nil, nil, fmt.Errorf("matrix: rand: %w", err)
		}
		for i := range m {
			copy(m[i], buf[i*n:])
		}
		det := matDet(m, n)
		if det%2 != 0 {
			inv, err := matInvMod256(m, n, det)
			if err == nil {
				return m, inv, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("matrix: could not find invertible matrix after 1000 attempts")
}

// MatrixTransform pads data to a multiple of n bytes and applies Hill-cipher-style
// matrix multiplication mod 256 to each n-byte column vector.
func MatrixTransform(data []byte, key [][]byte) ([]byte, error) {
	n := len(key)
	if n == 0 || len(key[0]) != n {
		return nil, fmt.Errorf("matrix: key must be n×n, got irregular shape")
	}
	padded := pkcs7Pad(data, n)
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += n {
		for row := 0; row < n; row++ {
			var acc int
			for col := 0; col < n; col++ {
				acc += int(key[row][col]) * int(padded[i+col])
			}
			out[i+row] = byte(acc % 256)
		}
	}
	return out, nil
}

// ReverseMatrixTransform applies the inverse key matrix to undo MatrixTransform.
func ReverseMatrixTransform(data []byte, inverse [][]byte) ([]byte, error) {
	n := len(inverse)
	if n == 0 || len(inverse[0]) != n {
		return nil, fmt.Errorf("matrix: inverse must be n×n")
	}
	if len(data)%n != 0 {
		return nil, fmt.Errorf("matrix: data length %d not a multiple of n=%d", len(data), n)
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += n {
		for row := 0; row < n; row++ {
			var acc int
			for col := 0; col < n; col++ {
				acc += int(inverse[row][col]) * int(data[i+col])
			}
			out[i+row] = byte(acc % 256)
		}
	}
	return pkcs7Unpad(out, n)
}

func matDet(m [][]byte, n int) int {
	switch n {
	case 1:
		return int(m[0][0])
	case 2:
		return int(m[0][0])*int(m[1][1]) - int(m[0][1])*int(m[1][0])
	case 3:
		return int(m[0][0])*(int(m[1][1])*int(m[2][2])-int(m[1][2])*int(m[2][1])) -
			int(m[0][1])*(int(m[1][0])*int(m[2][2])-int(m[1][2])*int(m[2][0])) +
			int(m[0][2])*(int(m[1][0])*int(m[2][1])-int(m[1][1])*int(m[2][0]))
	case 4:
		det := 0
		for col := 0; col < 4; col++ {
			sign := 1
			if col%2 != 0 {
				sign = -1
			}
			det += sign * int(m[0][col]) * matDet(minor(m, 0, col, 4), 3)
		}
		return det
	}
	return 0
}

func minor(m [][]byte, skipRow, skipCol, n int) [][]byte {
	sub := make([][]byte, n-1)
	ri := 0
	for r := 0; r < n; r++ {
		if r == skipRow {
			continue
		}
		sub[ri] = make([]byte, n-1)
		ci := 0
		for c := 0; c < n; c++ {
			if c == skipCol {
				continue
			}
			sub[ri][ci] = m[r][c]
			ci++
		}
		ri++
	}
	return sub
}

func matInvMod256(m [][]byte, n, detVal int) ([][]byte, error) {
	detMod := ((detVal % 256) + 256) % 256
	detInv := modInverse256(detMod)
	if detInv < 0 {
		return nil, fmt.Errorf("matrix: det=%d has no mod-256 inverse", detMod)
	}
	adj := make([][]byte, n)
	for i := range adj {
		adj[i] = make([]byte, n)
	}
	for r := 0; r < n; r++ {
		for c := 0; c < n; c++ {
			sign := 1
			if (r+c)%2 != 0 {
				sign = -1
			}
			cofact := sign * matDet(minor(m, r, c, n), n-1)
			v := ((cofact*detInv)%256 + 256) % 256
			adj[c][r] = byte(v)
		}
	}
	return adj, nil
}

// modInverse256 returns x^-1 mod 256, or -1 if none exists (x must be odd).
func modInverse256(x int) int {
	a, b := x, 256
	s, t := 1, 0
	for b != 0 {
		q := a / b
		a, b = b, a-q*b
		s, t = t, s-q*t
	}
	if a != 1 {
		return -1
	}
	return ((s % 256) + 256) % 256
}
