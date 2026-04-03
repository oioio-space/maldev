// Package hash provides hashing utilities for integrity verification and
// API hashing.
//
// Technique: API hashing (ROR13) for runtime function resolution without
// exposing plaintext import names to static analysis.
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
// Limitations:
//   - ROR13 is case-sensitive — callers must match the case used in shellcode.
//   - MD5 and SHA-1 are cryptographically broken; use SHA-256+ for integrity.
//
// Example:
//
//	hex := hash.SHA256(payload)
//	apiHash := hash.ROR13("LoadLibraryA")  // 0xEC0E4E8E
package hash
