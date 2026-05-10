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

// SeededSBox derives a deterministic 256-byte S-Box (permutation of
// [0,255]) and its inverse from a caller-supplied seed. The same
// seed always yields the same (sbox, inverse) pair — the operational
// contract a polymorphic stub-side decoder needs.
//
// Why operators want this:
//
//   - Per-pack polymorphism: derive seed from the master secret
//     (HKDF with a per-pack label) and ship the seed alongside the
//     payload. The stub re-derives the SAME SBox at runtime — no
//     need to embed all 256 bytes of the table.
//   - Wire-format compactness: 16-byte seed vs 256-byte table.
//   - Stub-side reproducibility: the stub computes the inverse SBox
//     by re-running this function with the seed it just decoded —
//     no separate inverse table to embed.
//
// Implementation: HKDF-SHA256 expands seed → 256 bytes of "shuffle
// tape", then Fisher-Yates with the same modular reduction as
// [NewSBox] (max 1/256 bias on the early swaps — negligible for
// signature-breaking purposes).
//
// Errors only on HKDF underflow (impossible for the fixed 256-byte
// extraction).
func SeededSBox(seed []byte) (sbox [256]byte, inverse [256]byte, err error) {
	tape, err := DeriveKey(seed, "sbox-fisher-yates", 256)
	if err != nil {
		return sbox, inverse, fmt.Errorf("sbox: derive seed: %w", err)
	}
	for i := range sbox {
		sbox[i] = byte(i)
	}
	for i := 255; i > 0; i-- {
		j := int(tape[i]) % (i + 1)
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
