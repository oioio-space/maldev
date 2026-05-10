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

// Example_passphraseToCiphertextPipeline shows the canonical operator
// pipeline for the v0.79.0 crypto stack:
//
//	Argon2id (passphrase + salt → master key)
//	  ↓
//	HKDF       (master → encKey + macKey)
//	  ↓
//	AES-CTR + HMAC-SHA256 (encrypt-then-MAC)
//
// Use this when an operator types a passphrase and the build pipeline
// needs both confidentiality and integrity over a payload, without
// the AEAD-tag wire-format overhead AES-GCM would add.
func Example_passphraseToCiphertextPipeline() {
	passphrase := []byte("operator-passphrase-2026")
	salt := []byte("per-deploy-salt-16b") // ≥ 8 bytes, deployment-unique

	// 1. Argon2id: passphrase → 32-byte master key (memory-hard).
	master, err := crypto.DeriveKeyFromPassword(passphrase, salt, 32)
	if err != nil {
		fmt.Println("argon2:", err)
		return
	}

	// 2. HKDF: split master into two purpose-bound subkeys.
	encKey, _ := crypto.DeriveKey(master, "payload-encrypt", 32)
	macKey, _ := crypto.DeriveKey(master, "payload-mac", 32)

	// 3. AES-CTR encrypt + HMAC over the ciphertext.
	plaintext := []byte("shellcode bytes")
	ct, err := crypto.EncryptAESCTR(encKey, plaintext)
	if err != nil {
		fmt.Println("encrypt:", err)
		return
	}
	tag := crypto.HMACSHA256(macKey, ct)
	blob := append(ct, tag...) // ciphertext || tag (16 IV + body + 32 tag)

	// 4. Stub-side: verify tag in constant time, then decrypt.
	if !crypto.VerifyHMACSHA256(macKey, blob[:len(blob)-32], blob[len(blob)-32:]) {
		fmt.Println("integrity check failed")
		return
	}
	pt, err := crypto.DecryptAESCTR(encKey, blob[:len(blob)-32])
	if err != nil {
		fmt.Println("decrypt:", err)
		return
	}
	fmt.Printf("recovered: %s\n", pt)

	// Output: recovered: shellcode bytes
}
