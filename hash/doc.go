// Package hash provides cryptographic and fuzzy hash primitives for
// integrity verification, API hashing, and similarity detection.
//
// Layers:
//
//   - Cryptographic: MD5 / SHA-1 / SHA-256 / SHA-512 → lowercase hex
//     strings.
//   - API hashing: ROR13 (rotate-right-13 + add) used by shellcode to
//     resolve Windows APIs at runtime without plaintext import names.
//     `ROR13Module` matches the convention that hashes the function
//     name with a trailing null terminator (PEB-walk shellcode style).
//   - Fuzzy hashing: ssdeep (CTPH — locality-sensitive) and TLSH (Trend
//     Locality-Sensitive Hash) for related-sample detection.
//
// # MITRE ATT&CK
//
// N/A (utility primitives consumed by other packages such as
// `win/api.ResolveByHash`).
//
// # Detection level
//
// very-quiet
//
// Pure hash operations. No system interaction.
//
// # Example
//
// See [ExampleROR13] and [ExampleSHA256] in hash_example_test.go.
//
// # See also
//
//   - docs/techniques/syscalls/api-hashing.md (ROR13 use case)
//   - [github.com/oioio-space/maldev/win/api] — `ResolveByHash`
//
// [github.com/oioio-space/maldev/win/api]: https://pkg.go.dev/github.com/oioio-space/maldev/win/api
package hash
