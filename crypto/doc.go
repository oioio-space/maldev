// Package crypto provides cryptographic primitives for payload
// encryption / decryption and lightweight obfuscation.
//
// Four layers:
//
//   - **Strong AEAD** (encrypt + authenticate, single primitive):
//     AES-256-GCM (`EncryptAESGCM` / `DecryptAESGCM`) and
//     XChaCha20-Poly1305 (`EncryptChaCha20` / `DecryptChaCha20`).
//     Random nonce prepended to ciphertext.
//   - **Raw stream / CTR** (encrypt only, integrity bring-your-own):
//     AES-CTR (`EncryptAESCTR` / `DecryptAESCTR`) and raw XChaCha20
//     (`EncryptChaCha20Raw` / `DecryptChaCha20Raw`). Drops the 16-byte
//     AEAD tag — useful when stage-2 payload self-validates or when
//     stub-size budget matters.
//   - **Lightweight block** (compact asm decoders for stage-1 stubs):
//     TEA / XTEA (8-byte block, 16-byte key), Speck-128/128 (ARX,
//     ~30 B asm per round), RC4 stream cipher, ArithShift
//     (position-dependent byte add), XOR with repeating key.
//   - **Signature-breaking transforms**: SBox (`NewSBox` random,
//     `SeededSBox` deterministic-from-seed), MatrixTransform (Hill
//     cipher mod 256, n ∈ {2,3,4}). Break static byte-frequency YARA
//     signatures on payloads — not strong cryptography.
//
// Key-derivation helpers:
//
//   - `NewAESKey`, `NewChaChaKey` — sane-default random key generation.
//   - `DeriveKey` / `DeriveKeySalted` (HKDF-SHA256, RFC 5869) — expand
//     one shared secret into multiple per-purpose subkeys via labels.
//   - `DeriveKeyFromPassword` / `DeriveKeyFromPasswordWithParams`
//     (Argon2id, RFC 9106 / OWASP 2024) — operator passphrase →
//     32-byte AES key for build-host packing flows.
//
// Integrity helpers:
//
//   - `HMACSHA256` / `VerifyHMACSHA256` — encrypt-then-MAC pattern
//     pairing with raw-stream ciphers. Constant-time tag compare.
//
// Cleanup helpers:
//
//   - `Wipe` — compiler-resistant memclear (mirrors cleanup/memory.SecureZero).
//   - `UseDecrypted(decrypt, fn)` — runs decrypt, hands plaintext to fn,
//     zeroes the buffer via defer. Closes the "did the operator
//     remember to wipe?" footgun.
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
// # Required privileges
//
// unprivileged. Pure-Go transforms over caller-supplied byte
// slices; no syscall, no token, no file I/O. AEAD nonces come
// from `crypto/rand` (OS CSPRNG), which itself runs at any
// privilege.
//
// # Platform
//
// Cross-platform. Pure-Go primitives only — `crypto/aes`,
// `golang.org/x/crypto/chacha20poly1305`, `crypto/rc4`,
// `crypto/rand`. No build tags, no GOOS-specific paths.
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
