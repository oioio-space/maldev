//go:build amd64 && windows

package packer

import "golang.org/x/sys/windows"

// hostWinBuild returns the Windows build number via RtlGetVersion. The
// API is documented to never fail (always STATUS_SUCCESS) and the Go
// wrapper in golang.org/x/sys/windows reflects that with a no-arg
// signature returning a populated [windows.OsVersionInfoEx]. nil should
// never come back; defensive return 0 covers the contract.
//
// The bundle stub-side asm (see [stage1.EmitPEBBuildRead]) reads the
// same DWORD straight from the PEB without an API call, so the host-
// side preview produced here matches the runtime evaluator byte-for-
// byte on a given Windows host.
func hostWinBuild() uint32 {
	info := windows.RtlGetVersion()
	if info == nil {
		return 0
	}
	return info.BuildNumber
}
