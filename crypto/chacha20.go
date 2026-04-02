package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptChaCha20 encrypts plaintext using XChaCha20-Poly1305 with a random nonce.
// The nonce is prepended to the returned ciphertext.
func EncryptChaCha20(key, plaintext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// DecryptChaCha20 decrypts XChaCha20-Poly1305 ciphertext produced by EncryptChaCha20.
func DecryptChaCha20(key, ciphertext []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key must be %d bytes", chacha20poly1305.KeySize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	pt, err := aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("ChaCha20-Poly1305 decryption failed: %w", err)
	}
	return pt, nil
}

// NewChaCha20Key generates a cryptographically random key for XChaCha20-Poly1305.
func NewChaCha20Key() ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	_, err := io.ReadFull(rand.Reader, key)
	return key, err
}
