//go:build windows

package api

import (
	"errors"
	"fmt"
	"unsafe"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// ErrProcNotFound is returned when a LazyProc cannot be resolved (e.g., DLL
// not loaded or export missing). Callers should use errors.Is to handle this
// as a non-fatal condition.
var ErrProcNotFound = errors.New("proc not available, nothing to patch")

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
// Returns ErrProcNotFound if the proc cannot be resolved.
func PatchProc(proc *windows.LazyProc, patch []byte) error {
	if err := proc.Find(); err != nil {
		return ErrProcNotFound
	}
	return PatchMemory(proc.Addr(), patch)
}

// PatchMemoryWithCaller patches memory using the specified syscall Caller.
// If caller is nil, falls back to standard PatchMemory (WinAPI).
func PatchMemoryWithCaller(addr uintptr, patch []byte, caller *wsyscall.Caller) error {
	if caller == nil {
		return PatchMemory(addr, patch)
	}

	size := uintptr(len(patch))
	var oldProtect uint32

	// Use NtProtectVirtualMemory via the caller.
	process := ^uintptr(0) // current process pseudo-handle
	baseAddr := addr
	regionSize := size

	r, err := caller.Call("NtProtectVirtualMemory",
		process,
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(windows.PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r != 0 {
		return fmt.Errorf("NtProtectVirtualMemory: %w", err)
	}

	// Write patch bytes.
	for i, b := range patch {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	// Restore original protection.
	baseAddr = addr
	regionSize = size
	var dummy uint32
	caller.Call("NtProtectVirtualMemory",
		process,
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&dummy)),
	)

	return nil
}

// PatchProcWithCaller patches a LazyProc's entry point using the specified Caller.
// Returns ErrProcNotFound if the proc cannot be resolved.
// If caller is nil, falls back to standard PatchProc (WinAPI).
func PatchProcWithCaller(proc *windows.LazyProc, patch []byte, caller *wsyscall.Caller) error {
	if err := proc.Find(); err != nil {
		return ErrProcNotFound
	}
	return PatchMemoryWithCaller(proc.Addr(), patch, caller)
}
