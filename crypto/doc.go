// Package crypto provides cryptographic primitives for payload encryption
// and decryption.
//
// Technique: Payload encryption/decryption for obfuscation at rest and in transit.
// MITRE ATT&CK: N/A (utility — no direct system interaction).
// Detection: N/A — pure cryptographic operations.
// Platform: Cross-platform.
//
// How it works: Wraps Go standard library ciphers (AES-256-GCM, XChaCha20-Poly1305,
// RC4) with nonce management and key generation. AEAD ciphers (AES-GCM, ChaCha20)
// prepend a random nonce to the ciphertext so that each encryption produces unique
// output. XOR uses a repeating key for lightweight obfuscation.
//
// Limitations:
//   - RC4 is deprecated and provided only for legacy compatibility.
//   - XOR is not encryption — it is trivially reversible obfuscation.
//
// Example:
//
//	key, _ := crypto.NewAESKey()
//	ciphertext, _ := crypto.EncryptAESGCM(key, shellcode)
//	plaintext, _ := crypto.DecryptAESGCM(key, ciphertext)
package crypto
