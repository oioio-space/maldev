package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF helpers (RFC 5869) for deriving multiple independent subkeys
// from a single master secret. Closes the "I have one shared secret
// and need a different key for each of N purposes" gap that operators
// otherwise paper over with hand-rolled SHA-256 slicing.
//
// HKDF is a two-step KDF:
//
//   - Extract: HMAC(salt, secret) → uniformly random PRK (pseudo-
//     random key). Salt MAY be empty — the construction tolerates
//     it but loses the salt's binding to a deployment.
//   - Expand: PRK + label + length → length bytes. Different labels
//     produce statistically independent outputs from the same PRK.
//
// Why prefer HKDF over manual sha256.Sum256(secret)[a:b] slicing:
//
//   - Slicing assumes the secret is uniformly random. If it's an
//     operator-typed passphrase, the SHA-256 output IS uniform but
//     the EXTRACTED entropy stays bounded by the input — slicing
//     half of a 32-byte hash gives 128 bits of entropy from a 64-bit
//     passphrase, not 128 bits.
//   - Different labels matter. With slicing, deriving "magic" and
//     "build" subkeys reuses the same hash bytes — flipping a bit
//     in "magic" and matching ciphertext blocks against "build"
//     becomes a confused-deputy attack vector.
//   - HKDF is the standard. crypto/cipher, golang.org/x/crypto/cryptobyte,
//     TLS 1.3, Signal — they all use HKDF for subkey derivation.
//
// Backed by [golang.org/x/crypto/hkdf] under the hood; this wrapper
// provides sane-default ergonomics (SHA-256, panic-free length
// validation, single-call API for the common case).

// DeriveKey runs HKDF-SHA256 with empty salt and the given label
// to produce a length-byte subkey from secret. The label binds the
// derived key to a specific purpose — passing "stub-xor" and "bundle-
// magic" yields two statistically independent keys from the same
// secret.
//
// Empty salt is appropriate when the secret is itself uniformly
// random (e.g. a 32-byte AES key). For operator passphrases, prefer
// [DeriveKeySalted] with a deployment-unique salt.
//
// Errors only on impossible HKDF underflow (length > 255 * 32 =
// 8160 bytes) — practical operator usage stays well below this.
func DeriveKey(secret []byte, label string, length int) ([]byte, error) {
	return DeriveKeySalted(secret, nil, label, length)
}

// DeriveKeySalted is the full HKDF-Extract-then-Expand variant.
// Use when secret is not uniformly random (passphrase, low-entropy
// pre-shared key) — the salt absorbs whatever entropy the secret
// has and produces a uniform PRK before expansion.
//
// Salt should be deployment-unique but does not need to be secret;
// a per-build random byte string committed to the binary is fine.
//
// Returns ErrHKDFLengthTooLarge if length exceeds HKDF-SHA256's
// hard limit (255 * 32 bytes = 8160 bytes). Operators needing more
// derive multiple subkeys with different labels.
func DeriveKeySalted(secret, salt []byte, label string, length int) ([]byte, error) {
	const hkdfSHA256Max = 255 * 32
	if length < 0 {
		return nil, fmt.Errorf("crypto: hkdf length %d negative", length)
	}
	if length > hkdfSHA256Max {
		return nil, fmt.Errorf("crypto: hkdf length %d exceeds RFC 5869 limit %d for SHA-256: %w",
			length, hkdfSHA256Max, ErrHKDFLengthTooLarge)
	}
	r := hkdf.New(sha256.New, secret, salt, []byte(label))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("crypto: hkdf read: %w", err)
	}
	return out, nil
}

// ErrHKDFLengthTooLarge is returned by [DeriveKey] / [DeriveKeySalted]
// when the requested key length exceeds 255 * 32 bytes (the RFC 5869
// limit for HKDF-SHA256). Sentinel for operators wanting to detect
// the case explicitly.
var ErrHKDFLengthTooLarge = fmt.Errorf("hkdf length exceeds 255*HashLen")
