// Package random provides cryptographically secure random generation functions.
//
// Technique: Cryptographic random generation for keys, nonces, and jitter.
// MITRE ATT&CK: N/A (utility — no direct system interaction).
// Detection: N/A — uses crypto/rand (OS entropy source).
// Platform: Cross-platform.
//
// How it works: All functions use crypto/rand.Reader (CSPRNG backed by OS
// entropy) for random generation. RandomString produces alphanumeric strings
// via per-character uniform selection from a 62-char charset. RandomInt and
// RandomDuration use math/big for uniform distribution over arbitrary ranges.
//
// Limitations:
//   - RandomString charset is fixed to [a-zA-Z0-9]; use RandomBytes for arbitrary data.
//   - RandomInt range is limited to Go int size (platform-dependent).
//
// Example:
//
//	key, _ := random.RandomBytes(32)
//	jitter, _ := random.RandomDuration(100*time.Millisecond, 500*time.Millisecond)
package random
