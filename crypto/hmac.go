package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
)

// HMAC-SHA256 helpers — covers the operational gap between AEAD
// (full encrypt+authenticate in one primitive) and raw-stream
// ciphers (no authentication). Pattern: encrypt with [EncryptAESCTR]
// or [EncryptChaCha20Raw], then attach an HMAC-SHA256 tag of the
// ciphertext for stub-side integrity verification.
//
// Why expose this instead of expecting callers to use [crypto/hmac]
// directly:
//
//   - Constant-time compare. [VerifyHMACSHA256] uses [hmac.Equal]
//     under the hood (equivalent to crypto/subtle.ConstantTimeCompare).
//     Callers comparing tags with bytes.Equal leak timing info.
//   - Sane defaults. SHA-256 is the modern minimum; SHA-1-MAC is
//     never the right choice in 2026.
//   - Single-line API. Most operator code is encrypt → MAC →
//     concatenate; one helper per direction reduces boilerplate.

// HMACSHA256 returns the 32-byte HMAC-SHA256 tag of data under key.
// Key may be any length — short keys are zero-padded, long keys
// are SHA-256-hashed first (RFC 2104 specification).
func HMACSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyHMACSHA256 returns true iff `tag` matches HMAC-SHA256(key, data).
// Constant-time compare — does not short-circuit on the first
// mismatched byte. Use this instead of bytes.Equal when validating
// authentication tags.
func VerifyHMACSHA256(key, data, tag []byte) bool {
	expected := HMACSHA256(key, data)
	return hmac.Equal(expected, tag)
}
