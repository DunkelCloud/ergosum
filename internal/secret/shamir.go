package secret

import (
	"crypto/rand"
	"errors"
)

// Shamir's scheme over GF(2^8) with the AES polynomial x^8 + x^4 + x^3 +
// x + 1, byte by byte. Share i (1-based) is the polynomial's value at
// x = i. The arithmetic avoids tables and branches on secret bytes.

// gfMul multiplies in GF(2^8).
func gfMul(a, b byte) byte {
	var p byte
	for range 8 {
		p ^= -(b & 1) & a
		carry := -(a >> 7)
		a = a<<1 ^ carry&0x1b
		b >>= 1
	}
	return p
}

// gfInv returns a^254, the inverse of a nonzero a.
func gfInv(a byte) byte {
	x := gfMul(a, a) // a^2
	r := x
	for range 6 { // r = a^2 · a^4 · … · a^128 = a^254
		x = gfMul(x, x)
		r = gfMul(r, x)
	}
	return r
}

// split returns n shares of secret, any k of which recover it.
func split(secret []byte, n, k int) ([][]byte, error) {
	if k < 1 || k > n || n > 255 {
		return nil, errors.New("secret: bad threshold")
	}
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, len(secret))
	}
	coef := make([]byte, k-1)
	for j, s := range secret {
		if _, err := rand.Read(coef); err != nil {
			return nil, err
		}
		for i := range n {
			x := byte(i + 1)
			// Horner: s + x·(c1 + x·(c2 + …))
			var y byte
			for t := len(coef) - 1; t >= 0; t-- {
				y = gfMul(y, x) ^ coef[t]
			}
			shares[i][j] = gfMul(y, x) ^ s
		}
	}
	return shares, nil
}

// combine recovers the secret from shares at distinct x (1-based indexes)
// by Lagrange interpolation at 0.
func combine(shares map[int][]byte) ([]byte, error) {
	if len(shares) == 0 {
		return nil, errors.New("secret: no shares")
	}
	xs := make([]byte, 0, len(shares))
	size := -1
	for x, s := range shares {
		if x < 1 || x > 255 {
			return nil, errors.New("secret: bad share index")
		}
		if size >= 0 && len(s) != size {
			return nil, errors.New("secret: shares differ in length")
		}
		size = len(s)
		xs = append(xs, byte(x))
	}
	out := make([]byte, size)
	for _, xi := range xs {
		// l_i(0) = Π_{m≠i} x_m / (x_m + x_i); subtraction is addition here.
		l := byte(1)
		for _, xm := range xs {
			if xm != xi {
				l = gfMul(l, gfMul(xm, gfInv(xm^xi)))
			}
		}
		for j, y := range shares[int(xi)] {
			out[j] ^= gfMul(l, y)
		}
	}
	return out, nil
}
