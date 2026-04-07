// Package hash provides hashing utilities for integrity verification,
// API hashing, and fuzzy hashing.
//
// Technique: API hashing (ROR13) for runtime function resolution without
// exposing plaintext import names to static analysis. Fuzzy hashing (ssdeep,
// TLSH) for similarity detection across binary variants.
// MITRE ATT&CK: N/A (utility — no direct system interaction).
// Detection: N/A — pure hashing operations.
// Platform: Cross-platform.
//
// How it works: Standard hash functions (MD5, SHA-1, SHA-256, SHA-512) return
// lowercase hex strings for easy comparison. ROR13 implements the classic
// shellcode API hashing algorithm (rotate-right-13 + add) used to resolve
// Windows API functions at runtime by comparing hashes instead of strings.
// ROR13Module appends a null terminator before hashing, matching the convention
// used in shellcode that resolves module names from the PEB.
//
// Fuzzy hashing: ssdeep uses context-triggered piecewise hashing to produce
// locality-sensitive hashes — small changes yield similar hashes, enabling
// detection of related samples. TLSH (Trend Locality Sensitive Hash) provides
// a distance metric between files; lower distance indicates higher similarity.
//
// Limitations:
//   - ROR13 is case-sensitive — callers must match the case used in shellcode.
//   - MD5 and SHA-1 are cryptographically broken; use SHA-256+ for integrity.
//   - ssdeep requires at least 4096 bytes of input to produce meaningful results.
//   - TLSH requires at least 50 bytes of input.
//
// Example:
//
//	hex := hash.SHA256(payload)
//	apiHash := hash.ROR13("LoadLibraryA")  // 0xEC0E4E8E
//	fuzzy, _ := hash.Ssdeep(payload)
//	tlshHash, _ := hash.TLSH(payload)
package hash
