// Package crypto provides cryptographic primitives for payload
// encryption / decryption and lightweight obfuscation.
//
// Three layers:
//
//   - **Strong AEAD**: AES-256-GCM (`EncryptAESGCM` / `DecryptAESGCM`)
//     and XChaCha20-Poly1305 (`EncryptChaCha20` / `DecryptChaCha20`).
//     Random nonce prepended to ciphertext.
//   - **Lightweight stream / block**: RC4 (`EncryptRC4`), TEA / XTEA
//     16-byte block ciphers, ArithShift (position-dependent byte add),
//     XOR with repeating key.
//   - **Signature-breaking transforms**: SBox (random 256-byte
//     permutation + inverse), MatrixTransform (Hill cipher mod 256,
//     n ∈ {2,3,4}). Not strong cryptography — used to break static
//     signatures on payloads.
//
// Helpers: `NewAESKey`, `NewChaChaKey` for sane-default key
// generation.
//
// # Entropy + layering
//
// AEAD ciphers produce uniformly high-entropy output. A 200 KB
// near-Shannon-max region in a Go binary is itself a YARA-friendly
// signal (`entropy >= 7.5` rules, ML PE classifiers) — strong
// crypto alone hides plaintext but advertises "encrypted blob
// here". Pair the AEAD outer envelope with a non-uniform inner
// transform (`ArithShift` for cheap position-dependent skew, or
// split across multiple sections) so the per-section entropy
// histogram looks ordinary. The "Layered envelope" section in
// docs/techniques/crypto/payload-encryption.md walks through the
// canonical AES → MatrixTransform → ArithShift → SBox stack.
//
// # MITRE ATT&CK
//
//   - T1027 (Obfuscated Files or Information)
//   - T1027.013 (Encrypted/Encoded File)
//
// # Detection level
//
// very-quiet
//
// Pure cryptographic operations. No system interaction.
//
// # Example
//
// See [ExampleEncryptAESGCM] and [ExampleEncryptChaCha20] in
// crypto_example_test.go.
//
// # See also
//
//   - docs/techniques/crypto/payload-encryption.md
//   - [github.com/oioio-space/maldev/encode] — text encoding (Base64, UTF-16LE)
//   - [github.com/oioio-space/maldev/hash] — hashing primitives
//
// [github.com/oioio-space/maldev/encode]: https://pkg.go.dev/github.com/oioio-space/maldev/encode
// [github.com/oioio-space/maldev/hash]: https://pkg.go.dev/github.com/oioio-space/maldev/hash
package crypto
