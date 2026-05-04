//go:build windows

// Package stealthopen reads files via NTFS Object ID (the 128-bit GUID
// stored in the MFT) instead of by path, bypassing path-based EDR
// hooks on `NtCreateFile` / `CreateFileW`.
//
// Workflow: GetObjectID once on the target file (which DOES touch the
// path-based hook briefly to read the MFT), then OpenByID (volume +
// GUID) for every subsequent access — the GUID-based open handles are
// not surfaced by path-watching filter drivers. Useful for repeated
// reads of `ntdll.dll` during unhooking, payload reads from a known
// dropper file, etc.
//
// The Opener interface is implemented by Standard (path-based, the
// fallback) and Stealth (Object-ID-based). Consumers like
// [github.com/oioio-space/maldev/evasion/unhook] take an Opener so
// they can route reads through the GUID path with one config knob.
//
// # MITRE ATT&CK
//
//   - T1036 (Masquerading) — file-access path masquerade
//
// # Detection level
//
// quiet
//
// Object-ID access is not logged by most EDR path filters. The
// initial GetObjectID still goes through path-based hooks, so the
// strategy is "open once, reuse the GUID".
//
// # Required privileges
//
// unprivileged for files the implant has standard read
// access to. `GetObjectID` performs a one-shot path-based
// open; subsequent `OpenByID` calls reach the file via the
// volume handle + Object-ID GUID and inherit the same
// DACL gate as a normal open of that file. Reading
// `ntdll.dll` is unprivileged for any user; reading
// system-protected paths needs admin / SYSTEM as usual.
//
// # Platform
//
// Windows-only (`//go:build windows`). Object-ID open is
// an NTFS-specific feature; FAT / exFAT volumes have no
// MFT-stored object IDs and the technique falls back to
// path open.
//
// # Example
//
// See [ExampleOpenByID] in stealthopen_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/stealthopen.md
//   - [github.com/oioio-space/maldev/evasion/unhook] — primary consumer
//
// [github.com/oioio-space/maldev/evasion/unhook]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook
package stealthopen
