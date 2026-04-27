package crypto_test

import (
	"fmt"

	"github.com/oioio-space/maldev/crypto"
)

// AES-256-GCM with a fresh key. Random nonce prepended to ciphertext.
// AEAD authenticates the result — tampering produces an error on decrypt.
func ExampleEncryptAESGCM() {
	key, _ := crypto.NewAESKey()
	plaintext := []byte("shellcode goes here")

	ct, err := crypto.EncryptAESGCM(key, plaintext)
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}

	pt, err := crypto.DecryptAESGCM(key, ct)
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	fmt.Println(string(pt))
	// Output: shellcode goes here
}

// XChaCha20-Poly1305 — drop-in replacement for AES-GCM with a 24-byte
// nonce (less likely to repeat under heavy use).
func ExampleEncryptChaCha20() {
	key, _ := crypto.NewChaCha20Key()
	ct, _ := crypto.EncryptChaCha20(key, []byte("payload"))
	pt, _ := crypto.DecryptChaCha20(key, ct)
	fmt.Println(string(pt))
	// Output: payload
}

// XOR with a repeating key — lightweight obfuscation, NOT encryption.
// Trivially reversible if the key is short or guessable.
func ExampleXORWithRepeatingKey() {
	key := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	scrambled, _ := crypto.XORWithRepeatingKey([]byte("hidden"), key)
	original, _ := crypto.XORWithRepeatingKey(scrambled, key)
	fmt.Println(string(original))
	// Output: hidden
}
