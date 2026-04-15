package crypto

import (
	"crypto/rand"
	"fmt"
)

// NewSBox generates a random 256-byte S-Box (permutation of 0–255) and its inverse.
// Used for non-linear byte substitution as a shellcode obfuscation layer.
func NewSBox() (sbox [256]byte, inverse [256]byte, err error) {
	for i := range sbox {
		sbox[i] = byte(i)
	}
	b := make([]byte, 256)
	if _, err = rand.Read(b); err != nil {
		return sbox, inverse, fmt.Errorf("sbox: rand: %w", err)
	}
	for i := 255; i > 0; i-- {
		j := int(b[i]) % (i + 1)
		sbox[i], sbox[j] = sbox[j], sbox[i]
	}
	for i, v := range sbox {
		inverse[v] = byte(i)
	}
	return sbox, inverse, nil
}

// SubstituteBytes applies a 256-byte substitution table to data.
// The table must be a valid permutation of [0,255] for ReverseSubstituteBytes to work.
func SubstituteBytes(data []byte, sbox [256]byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = sbox[b]
	}
	return out
}

// ReverseSubstituteBytes applies the inverse substitution table.
func ReverseSubstituteBytes(data []byte, inverse [256]byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = inverse[b]
	}
	return out
}
