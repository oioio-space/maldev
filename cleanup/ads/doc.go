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
// # Required privileges
//
// unprivileged for files the implant has standard read/write
// access to (own profile, world-writable paths). Streams under
// system-protected paths (`C:\Windows\System32\`, root of the
// system drive for non-SYSTEM users) inherit the same DACL gate
// as the default stream — admin / SYSTEM. ADS creation needs no
// extra privilege beyond standard `CreateFileW` write access on
// the host file.
//
// # Platform
//
// Windows-only. The API surface (`CreateFileW` with `:streamname`
// syntax) only resolves on Windows; cross-compile to Linux yields
// a build error rather than a silent stub. NTFS-only at runtime
// — calls against FAT or exFAT volumes succeed at the API level
// but the stream data is dropped silently.
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
