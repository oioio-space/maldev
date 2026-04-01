//go:build windows

package api

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PatchMemory overwrites bytes at addr with patch, temporarily setting
// PAGE_EXECUTE_READWRITE and restoring the original protection afterward.
// This is the canonical implementation — all evasion modules should use this.
func PatchMemory(addr uintptr, patch []byte) error {
	size := uintptr(len(patch))
	var oldProtect uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect RWX: %w", err)
	}
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}
	// Restore original protection; ignore errors on restore.
	var dummy uint32
	windows.VirtualProtect(addr, size, oldProtect, &dummy)
	return nil
}

// PatchProc patches a LazyProc's entry point with the given bytes.
// Returns nil if the proc cannot be found (e.g., DLL not loaded).
func PatchProc(proc *windows.LazyProc, patch []byte) error {
	if err := proc.Find(); err != nil {
		return nil // proc not available, nothing to patch
	}
	return PatchMemory(proc.Addr(), patch)
}
