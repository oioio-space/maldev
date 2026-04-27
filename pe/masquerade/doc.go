// Package masquerade clones a Windows PE's identity — manifest,
// icons, VERSIONINFO, optional Authenticode certificate — into
// a linkable `.syso` COFF object so a Go binary picks them up
// at compile time.
//
// Two usage modes:
//
//  1. Pre-built presets — zero-effort import-and-go:
//
//     import _ "github.com/oioio-space/maldev/pe/masquerade/preset/svchost"
//
//  2. Programmatic API — clone any PE on demand:
//
//     masquerade.Clone(`C:\Windows\System32\svchost.exe`,
//         "resource.syso", masquerade.AMD64, masquerade.AsInvoker)
//
// Composable extraction lets callers mutate fields between
// extraction and emission:
//
//	res, _ := masquerade.Extract(`C:\Windows\System32\svchost.exe`)
//	res.VersionInfo.OriginalFilename = "myservice.exe"
//	res.GenerateSyso("resource.syso", masquerade.AMD64,
//	    masquerade.AsInvoker)
//
// The [Build] + `With*` option chain is the modern entry point —
// strongly typed, easier to reuse across projects.
//
// # MITRE ATT&CK
//
//   - T1036.005 (Masquerading: Match Legitimate Name or Location) — VERSIONINFO + manifest + icon clone
//
// # Detection level
//
// quiet
//
// VERSIONINFO and manifest can be inspected (`Get-ItemProperty`,
// CFF Explorer, file-properties dialog) but rarely are. Naive
// allowlists keyed on OriginalFilename / CompanyName accept the
// cloned binary; behavioural EDRs ignore the metadata and
// score on actual runtime activity.
//
// # Example
//
// See [ExampleClone] and [ExampleBuild] in masquerade_example_test.go.
//
// # See also
//
//   - docs/techniques/pe/masquerade.md
//   - [github.com/oioio-space/maldev/pe/cert] — clone the publisher's cert too
//   - [github.com/oioio-space/maldev/pe/strip] — pair with strip post-link to remove Go fingerprints
//   - [github.com/oioio-space/maldev/cleanup/timestomp] — match the source PE's mtime/atime
//
// [github.com/oioio-space/maldev/pe/cert]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/cert
// [github.com/oioio-space/maldev/pe/strip]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/strip
// [github.com/oioio-space/maldev/cleanup/timestomp]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup/timestomp
package masquerade
