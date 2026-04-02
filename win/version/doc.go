//go:build windows

// Package version provides Windows version detection utilities for
// determining OS version, build number, and patch level.
//
// Platform: Windows
// Detection: Low -- uses standard RtlGetVersion and registry queries.
//
// Key features:
//   - Version detection via RtlGetVersion (avoids deprecated GetVersionEx)
//   - UBR (Update Build Revision) from registry for precise patch identification
//   - CVE-2024-30088 vulnerability check based on build and UBR
//   - Well-known version constants for all major Windows releases
//
// Example:
//
//	v := version.Current()
//	if v.IsLower(version.WINDOWS_10_1809) {
//	    fmt.Println("Unsupported Windows version")
//	}
package version
