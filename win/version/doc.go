//go:build windows

// Package version reports the running Windows OS version, build, and
// patch level — bypassing the manifest-compatibility shim that masks
// `GetVersionEx` results to the manifest-declared compatibility
// target.
//
// [Current] returns a [Version] with major/minor/build/UBR fields
// populated from the unhooked `RtlGetVersion` (kernel-side, returns
// the real version regardless of the running PE's manifest) plus a
// registry read for the UBR (Update Build Revision — the patch
// number Microsoft increments inside a build, e.g. 10.0.19045.5189
// where `5189` is the UBR). [AtLeast] gates code on a minimum build
// for technique compatibility, and [CVE202430088] reports the
// patched-or-not state of the kernel TOCTOU primitive consumed by
// [github.com/oioio-space/maldev/privesc/cve202430088].
//
// Useful for:
//
//   - Gating syscall SSN tables (per-build offsets in
//     [github.com/oioio-space/maldev/win/syscall]).
//   - Selecting the right UAC-bypass shim — many of those break
//     across build cuts.
//   - Pre-flight checks for kernel exploits (cve202430088 +
//     future entries).
//
// # MITRE ATT&CK
//
//   - T1082 (System Information Discovery)
//
// # Detection level
//
// very-quiet
//
// `RtlGetVersion` is a single ntdll call; the registry-UBR read uses
// the standard `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
// key that built-in tools (`winver`, `ver`) rely on.
//
// # Required privileges
//
// unprivileged. `RtlGetVersion` is a single ntdll call that
// always returns the real (kernel-side) version regardless of
// token. The UBR registry read targets
// `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, which
// is world-readable on a default install.
//
// # Platform
//
// Windows-only (`//go:build windows`).
//
// # Example
//
// See [ExampleCurrent] and [ExampleAtLeast] in version_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/README.md
//   - [github.com/oioio-space/maldev/win/syscall] — gating SSN tables on build
//   - [github.com/oioio-space/maldev/privesc/cve202430088] — version-gated kernel exploit
//
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
// [github.com/oioio-space/maldev/privesc/cve202430088]: https://pkg.go.dev/github.com/oioio-space/maldev/privesc/cve202430088
package version
