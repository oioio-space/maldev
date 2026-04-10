// Package random provides cryptographically secure random generation functions.
//
// Technique: Cryptographic random generation for keys, nonces, and jitter.
// MITRE ATT&CK: N/A (utility — no direct system interaction).
// Detection: N/A — uses crypto/rand (OS entropy source).
// Platform: Cross-platform.
//
// How it works: All functions use crypto/rand.Reader (CSPRNG backed by OS
// entropy) for random generation. String produces alphanumeric strings
// via per-character uniform selection from a 62-char charset. Int and
// Duration use math/big for uniform distribution over arbitrary ranges.
//
// Limitations:
//   - String charset is fixed to [a-zA-Z0-9]; use Bytes for arbitrary data.
//   - Int range is limited to Go int size (platform-dependent).
//
// Example:
//
//	key, _ := random.Bytes(32)
//	jitter, _ := random.Duration(100*time.Millisecond, 500*time.Millisecond)
package random
