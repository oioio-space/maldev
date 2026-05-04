// Package cert manipulates the PE Authenticode security directory
// — read, copy, strip, and write WIN_CERTIFICATE blobs without
// any Windows crypto API.
//
// The PE security directory (data directory index 4) carries a
// file offset + size pointing at WIN_CERTIFICATE structures
// appended after the last section. This package operates on
// those raw bytes:
//
//   - [Read] / [Has] inspect the security directory entry.
//   - [Write] appends certificate data and patches the directory.
//   - [Strip] truncates certificate data and zeroes the directory.
//   - [Copy] combines [Read] + [Write] across two PE files.
//   - [Import] persists raw certificate blobs from disk.
//
// Operationally the package is paired with pe/strip + pe/morph
// to clone a legitimate publisher's cert onto an unsigned
// implant — enough to trick file-property dialogs and naive
// signature audits, though Windows itself will reject the
// signature when verified.
//
// # MITRE ATT&CK
//
//   - T1553.002 (Subvert Trust Controls: Code Signing) — clone a third-party signature blob
//
// # Detection level
//
// quiet
//
// Certificate manipulation leaves no runtime artifacts; modified
// PE files fail signature verification when actually checked
// (`signtool verify`, Windows Defender SmartScreen) but pass
// at rest in directory listings, file properties, and basic
// EDR PE-metadata scans.
//
// # Required privileges
//
// unprivileged. Pure-byte manipulation of the PE security
// directory; no Windows crypto API, no syscall. The DACL on
// source / destination paths is the only upstream gate.
//
// # Platform
//
// Cross-platform. Pure-Go offline editor — analysts can
// extract or splice WIN_CERTIFICATE blobs from any host.
// `PatchPECheckSum` reproduces the MS `ImageHlp!CheckSumMappedFile`
// algorithm in pure Go for the same reason.
//
// # Example
//
// See [ExampleRead] and [ExampleCopy] in cert_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/certificate-theft.md
//   - [github.com/oioio-space/maldev/pe/strip] — sanitise before signing
//   - [github.com/oioio-space/maldev/pe/masquerade] — clone the publisher's manifest + version too
//
// [github.com/oioio-space/maldev/pe/strip]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip
// [github.com/oioio-space/maldev/pe/masquerade]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade
package cert
