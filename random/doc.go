// Package random provides cryptographically secure random generation
// helpers backed by `crypto/rand` (OS entropy).
//
//   - `Bytes(n)` — n random bytes.
//   - `String(n)` — n alphanumeric characters from `[a-zA-Z0-9]`.
//   - `Int(min, max)` — uniform integer in `[min, max]`.
//   - `Duration(min, max)` — uniform `time.Duration` in `[min, max]`.
//     Useful for callback jitter.
//
// # MITRE ATT&CK
//
// N/A (utility primitives).
//
// # Detection level
//
// very-quiet
//
// Reads from `RtlGenRandom` / `BCryptGenRandom` on Windows; standard
// CSPRNG everywhere.
//
// # Required privileges
//
// unprivileged. `crypto/rand` reads from the OS CSPRNG —
// `BCryptGenRandom` / `RtlGenRandom` on Windows, `getrandom(2)` /
// `/dev/urandom` on Linux — both available to any token.
//
// # Platform
//
// Cross-platform. Stdlib `crypto/rand` + `math/big`. No build
// tags.
//
// # Example
//
// See [ExampleBytes] and [ExampleDuration] in random_example_test.go.
//
// # See also
//
//   - [github.com/oioio-space/maldev/crypto] — primary consumer
//
// [github.com/oioio-space/maldev/crypto]: https://pkg.go.dev/github.com/oioio-space/maldev/crypto
package random
