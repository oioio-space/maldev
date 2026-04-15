//go:build windows

package cet

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// Marker is the ENDBR64 opcode that every CET-valid indirect call target
// must start with.
var Marker = []byte{0xF3, 0x0F, 0x1E, 0xFA}

// processUserShadowStackPolicy is PROCESS_MITIGATION_POLICY::ProcessUserShadowStackPolicy
// (winnt.h). Passed as the first arg to Set/GetProcessMitigationPolicy.
const processUserShadowStackPolicy = 17

// userShadowStackPolicy mirrors PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY.
// Bit 0 = EnableUserShadowStack — the flag that gates everything.
type userShadowStackPolicy uint32

const enableUserShadowStack userShadowStackPolicy = 1 << 0

// Enforced reports whether the current process has user-mode shadow
// stacks enabled. Returns false on non-CET hardware, pre-Win11 hosts,
// or processes explicitly opted-out.
func Enforced() bool {
	var p userShadowStackPolicy
	r, _, _ := api.ProcGetProcessMitigationPolicy.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(processUserShadowStackPolicy),
		uintptr(unsafe.Pointer(&p)),
		unsafe.Sizeof(p),
	)
	if r == 0 {
		return false
	}
	return p&enableUserShadowStack != 0
}

// Disable relaxes ProcessUserShadowStackPolicy for the current process.
// Returns an error when the image cannot be relaxed at runtime — most
// commonly because it was compiled with /CETCOMPAT (StrictMode). A
// standard Go binary without /CETCOMPAT can be relaxed even when the
// OS has enforcement on by default.
func Disable() error {
	var p userShadowStackPolicy // zero = no bits, all CET features off
	r, _, err := api.ProcSetProcessMitigationPolicy.Call(
		uintptr(processUserShadowStackPolicy),
		uintptr(unsafe.Pointer(&p)),
		unsafe.Sizeof(p),
	)
	if r == 0 {
		return fmt.Errorf("SetProcessMitigationPolicy(ShadowStack): %w", err)
	}
	return nil
}

// Wrap prepends Marker to sc unless sc already begins with it. Idempotent;
// safe to call on any shellcode, including zero-length.
func Wrap(sc []byte) []byte {
	if startsWithMarker(sc) {
		return sc
	}
	out := make([]byte, 0, len(sc)+len(Marker))
	out = append(out, Marker...)
	out = append(out, sc...)
	return out
}

func startsWithMarker(sc []byte) bool {
	if len(sc) < len(Marker) {
		return false
	}
	for i, b := range Marker {
		if sc[i] != b {
			return false
		}
	}
	return true
}
