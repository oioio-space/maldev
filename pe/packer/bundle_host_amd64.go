//go:build amd64 && (linux || windows)

package packer

import (
	"github.com/oioio-space/maldev/recon/antivm"
)

// HostCPUIDVendor returns the 12-byte CPUID EAX=0 vendor string of the
// host CPU (e.g. {'G','e','n','u','i','n','e','I','n','t','e','l'}).
//
// Implemented via [antivm.CPUVendor], which calls Plan-9-asm
// `cpuidRaw(0, 0)` from the existing `recon/antivm` package — no mmap,
// no trampoline, no GC traps. The runtime stub-side asm
// ([stage1.EmitCPUIDVendorRead]) emits the same byte sequence inline
// for self-contained binaries that can't link to the recon package.
func HostCPUIDVendor() [12]byte {
	var out [12]byte
	copy(out[:], antivm.CPUVendor())
	return out
}

// MatchBundleHost is the operator-facing "would this payload fire on
// this host?" check. It reads the host's CPUID vendor (and on Windows,
// OSBuildNumber via RtlGetVersion — see bundle_host_windows.go), then
// calls [SelectPayload] against the supplied bundle.
//
// Returns -1 if no entry matches. Errors flow from [SelectPayload]
// (truncation, bad magic).
//
// On Linux the build number is reported as 0, so any entry with
// PT_WIN_BUILD + non-zero BuildMin will not match — which is the
// correct semantic since Linux bundles do not carry Windows build
// predicates.
func MatchBundleHost(bundle []byte) (int, error) {
	vendor := HostCPUIDVendor()
	build := hostWinBuild()
	return SelectPayload(bundle, vendor, build)
}

// MatchBundleHostWith is the per-build-profile-aware variant of
// [MatchBundleHost]. Validates the bundle's magic against
// `profile.Magic` (canonical default when zero) and dispatches via
// [SelectPayloadWith].
func MatchBundleHostWith(bundle []byte, profile BundleProfile) (int, error) {
	vendor := HostCPUIDVendor()
	build := hostWinBuild()
	return SelectPayloadWith(bundle, profile, vendor, build)
}
