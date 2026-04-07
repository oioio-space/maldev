// Package cert provides PE Authenticode certificate manipulation — read,
// copy, strip, and write certificate data in PE files.
//
// Technique: PE Authenticode certificate manipulation (read, copy, strip)
// MITRE ATT&CK: T1553.002 (Subvert Trust Controls: Code Signing)
// Platform: Cross-platform (operates on PE file bytes)
// Detection: Low — certificate manipulation leaves no runtime artifacts;
// modified PE files may fail signature verification.
//
// How it works:
//
// The PE security directory (data directory index 4) contains a file offset
// and size pointing to WIN_CERTIFICATE structures appended after the last
// section. This package reads, replaces, or removes that certificate blob
// by manipulating raw PE bytes — no Windows crypto APIs required.
//
//   - Read / Has inspect the security directory entry
//   - Write appends certificate data and patches the directory entry
//   - Strip truncates certificate data and zeroes the directory entry
//   - Copy combines Read + Write across two PE files
//   - Export / Import persist raw certificate blobs to disk
//
// Limitations:
//   - Does not validate Authenticode signatures or certificate chains
//   - Does not recompute PE checksum after modification
//   - Expects well-formed PE input; truncated files return ErrInvalidPE
package cert
