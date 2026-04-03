// Package encode provides encoding and decoding utilities for payload
// transformation.
//
// Technique: Payload encoding for transport, embedding, and obfuscation.
// MITRE ATT&CK: N/A (utility — no direct system interaction).
// Detection: N/A — pure encoding operations.
// Platform: Cross-platform.
//
// How it works: Converts binary payloads to text-safe representations using
// Base64 (standard and URL-safe), UTF-16LE (for Windows API string parameters),
// ROT13 (alphabetic rotation), and PowerShell-compatible encoding (Base64 of
// UTF-16LE). All operations are pure functions with no side effects.
//
// Limitations:
//   - ROT13 only rotates ASCII letters; non-alpha characters pass through unchanged.
//   - PowerShell encoding produces Base64(UTF-16LE), matching -EncodedCommand format.
//
// Example:
//
//	encoded := encode.Base64Encode(shellcode)
//	decoded, _ := encode.Base64Decode(encoded)
//	psCmd := encode.EncodePowerShell("Get-Process")
package encode
