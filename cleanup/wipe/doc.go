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
