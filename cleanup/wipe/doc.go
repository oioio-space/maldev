// Package wipe overwrites file contents with cryptographically random data
// before deletion to defeat trivial forensic recovery.
//
// File performs N passes of full-file random overwrite (each pass reading a
// fresh `crypto/rand` buffer) before calling `os.Remove`. The intent is to
// defeat undelete utilities and partition recovery; it does NOT defeat
// physical-layer recovery from spinning disks (residual magnetism) or wear-
// levelled SSD remap pools.
//
// # MITRE ATT&CK
//
//   - T1070.004 (Indicator Removal: File Deletion)
//
// # Detection level
//
// quiet
//
// File writes + deletion are high-volume events. The repeated full-file
// writes (especially on small files) form a weak signal but blend with
// log rotation, image conversion, etc.
//
// # Required privileges
//
// unprivileged for files the implant has read+write access to.
// Wiping under protected paths (`C:\Windows\System32\`,
// `/etc`) requires admin / root, same as any other write.
//
// # Platform
//
// Cross-platform. The implementation uses pure-Go `os` calls
// (`os.OpenFile`, `os.Remove`, `crypto/rand`); no platform-
// specific surface. Wear-levelled SSDs and NTFS resident
// `$DATA` (small files stored in the MFT) bypass the overwrite
// regardless of OS — see Limitations in the tech md.
//
// # Example
//
// See [ExampleFile] in wipe_example_test.go.
//
// # See also
//
//   - docs/techniques/cleanup/wipe.md
//   - [github.com/oioio-space/maldev/cleanup/selfdelete] — for in-place implant cleanup
//
// [github.com/oioio-space/maldev/cleanup/selfdelete]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/selfdelete
package wipe
