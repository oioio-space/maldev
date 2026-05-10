package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AES-CTR — unauthenticated counter-mode AES. Sits next to
// [EncryptAESGCM] in the API hierarchy; differs in two operationally
// meaningful ways:
//
//   - No 16-byte authentication tag. AES-GCM's tag adds 16 bytes
//     and a constant-time-compare check at decrypt — useful when
//     tampering matters, wasted when the next stage validates
//     itself. A 1 MiB stub-side encrypted blob spends 16 bytes
//     of GCM tag + an HMAC pass on every decrypt cycle; CTR drops
//     both.
//   - Symmetric encrypt/decrypt path. Same primitive, no tag
//     verification branch — turns into ~30 bytes of asm at the
//     critical path (load IV, init counter, XOR keystream).
//
// Use when:
//
//   - Stage-1 stub decrypts a stage-2 payload that ALREADY has
//     its own integrity (signed PE, AEAD-wrapped inner blob).
//     Doubling integrity wastes bytes and clock cycles.
//   - Wire format budget is tight (e.g. 4 KiB stub size cap) and
//     16 bytes of GCM tag matter.
//
// DO NOT use when:
//
//   - Plaintext integrity matters and isn't validated downstream.
//     CTR is malleable — flipping a ciphertext bit flips the
//     same plaintext bit silently. Pair with an HMAC outer or
//     prefer [EncryptAESGCM].
//
// Wire format: 16-byte random IV prepended to ciphertext.
// Plaintext length == ciphertext length - 16.

// EncryptAESCTR encrypts plaintext under AES-CTR with a random IV.
// Key must be 16, 24, or 32 bytes (AES-128/192/256). The IV is
// prepended to the returned ciphertext.
func EncryptAESCTR(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes-ctr cipher: %w", err)
	}
	out := make([]byte, aes.BlockSize+len(plaintext))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("crypto: aes-ctr iv: %w", err)
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out[aes.BlockSize:], plaintext)
	return out, nil
}

// DecryptAESCTR decrypts AES-CTR ciphertext produced by [EncryptAESCTR].
// Key must match. Returns the plaintext.
//
// No integrity check — caller is responsible for validating the
// returned bytes (e.g. checking a magic, parsing a length-prefixed
// frame, or verifying an outer HMAC).
func DecryptAESCTR(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("crypto: aes-ctr ciphertext %d bytes < %d (IV size)",
			len(ciphertext), aes.BlockSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: aes-ctr cipher: %w", err)
	}
	iv := ciphertext[:aes.BlockSize]
	body := ciphertext[aes.BlockSize:]
	out := make([]byte, len(body))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(out, body)
	return out, nil
}
