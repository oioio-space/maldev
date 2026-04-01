// Package morph provides UPX header mutation for PE files to prevent
// automatic unpacking and change file hashes.
//
// Technique: UPX signature replacement with random bytes.
// MITRE ATT&CK: T1027.002 (Obfuscated Files or Information: Software Packing)
// Platform: Cross-platform (operates on PE byte slices)
// Detection: Medium -- modified UPX headers prevent standard unpackers but
// the PE structure remains recognizable.
//
// Key features:
//   - UPXMorph: replace UPX signature with random bytes to break unpackers
//   - UPXFix: restore original UPX signature for debugging
package morph
