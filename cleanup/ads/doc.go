// Package ads provides CRUD operations for NTFS Alternate Data Streams.
//
// Alternate Data Streams (ADS) are hidden data storage areas attached to NTFS
// files. Every file has a default unnamed `:$DATA` stream; additional named
// streams (`file:streamname`) can store arbitrary bytes that don't appear in
// `dir`, Explorer, or most file-listing APIs. The package exposes Write /
// Read / List / Delete primitives over `Win32 CreateFileW` so callers can
// hide payloads, store implant state, or rename a default stream as part of
// the [selfdelete] dance.
//
// # MITRE ATT&CK
//
//   - T1564.004 (Hide Artifacts: NTFS File Attributes)
//
// # Detection level
//
// quiet
//
// File metadata events are logged but stream-level visibility requires
// dedicated tooling (Sysinternals Streams, `Get-Item -Stream *`,
// EDR-with-MFT-aware-scanner).
//
// # Example
//
// See [ExampleWrite] in ads_example_test.go.
//
// # See also
//
//   - docs/techniques/cleanup/ads.md
//   - [github.com/oioio-space/maldev/cleanup/selfdelete] — uses ADS rename
//
// [selfdelete]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/selfdelete
package ads
