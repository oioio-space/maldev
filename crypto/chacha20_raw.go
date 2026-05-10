package crypto

import (
	"fmt"

	"github.com/oioio-space/maldev/random"
	"golang.org/x/crypto/chacha20"
)

// Raw ChaCha20 (without Poly1305 authentication). Sits next to
// [EncryptChaCha20] (which is XChaCha20-Poly1305 AEAD) the same way
// [EncryptAESCTR] sits next to [EncryptAESGCM] — same primitive,
// no integrity tag, smaller wire format and tighter critical path.
//
// Use when:
//
//   - AES-NI is absent and the stub must avoid the AES S-box. ChaCha20
//     is constant-time across all CPUs (no table lookups), so it doesn't
//     leak timing info on cache-attack-prone targets.
//   - Stage-2 payload already validates itself (signed PE, AEAD inner).
//
// Wire format: 24-byte random nonce prepended to ciphertext (uses
// XChaCha20 — extended-nonce variant — which makes random nonces
// safe at the 2^96 collision limit. The standard ChaCha20 8-byte
// nonce would be borderline for random selection over a long
// operator timeline).
//
// Plaintext length == ciphertext length - 24.

// EncryptChaCha20Raw encrypts plaintext under XChaCha20 (24-byte
// nonce variant) with a random nonce. Key must be 32 bytes; the
// nonce is prepended to the returned ciphertext.
//
// No authentication. Caller validates plaintext integrity via an
// outer layer (e.g. [HMACSHA256]).
func EncryptChaCha20Raw(key, plaintext []byte) ([]byte, error) {
	if len(key) != chacha20.KeySize {
		return nil, fmt.Errorf("crypto: chacha20 key %d bytes, want %d", len(key), chacha20.KeySize)
	}
	out := make([]byte, chacha20.NonceSizeX+len(plaintext))
	nonce, err := random.Bytes(chacha20.NonceSizeX)
	if err != nil {
		return nil, fmt.Errorf("crypto: chacha20 nonce: %w", err)
	}
	copy(out[:chacha20.NonceSizeX], nonce)
	cipher, err := chacha20.NewUnauthenticatedCipher(key, out[:chacha20.NonceSizeX])
	if err != nil {
		return nil, fmt.Errorf("crypto: chacha20 cipher: %w", err)
	}
	cipher.XORKeyStream(out[chacha20.NonceSizeX:], plaintext)
	return out, nil
}

// DecryptChaCha20Raw decrypts ciphertext produced by [EncryptChaCha20Raw].
// Key must be 32 bytes. Returns the plaintext.
//
// No integrity check.
func DecryptChaCha20Raw(key, ciphertext []byte) ([]byte, error) {
	if len(key) != chacha20.KeySize {
		return nil, fmt.Errorf("crypto: chacha20 key %d bytes, want %d", len(key), chacha20.KeySize)
	}
	if len(ciphertext) < chacha20.NonceSizeX {
		return nil, fmt.Errorf("crypto: chacha20 ciphertext %d bytes < %d (nonce size)",
			len(ciphertext), chacha20.NonceSizeX)
	}
	nonce := ciphertext[:chacha20.NonceSizeX]
	body := ciphertext[chacha20.NonceSizeX:]
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("crypto: chacha20 cipher: %w", err)
	}
	out := make([]byte, len(body))
	cipher.XORKeyStream(out, body)
	return out, nil
}
