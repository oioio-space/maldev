//go:build windows

// Package ntapi provides typed wrappers for Native API functions (ntdll.dll).
// These bypass kernel32.dll hooks but are still hookable at the ntdll level.
//
// For full hook bypass, use win/syscall/direct or win/syscall/indirect.
//
// Usage:
//
//	addr, err := ntapi.NtAllocateVirtualMemory(handle, 0, size, MEM_COMMIT, PAGE_RW)
package ntapi

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// NtAllocateVirtualMemory allocates memory in a process.
func NtAllocateVirtualMemory(process windows.Handle, baseAddr, size uintptr, allocType, protect uint32) (uintptr, error) {
	addr := baseAddr
	regionSize := size
	r, _, _ := api.ProcNtAllocateVirtualMemory.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(allocType),
		uintptr(protect),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%08X", uint32(r))
	}
	return addr, nil
}

// NtWriteVirtualMemory writes data to a process's memory.
func NtWriteVirtualMemory(process windows.Handle, baseAddr uintptr, buffer []byte) (uintptr, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	var written uintptr
	r, _, _ := api.ProcNtWriteVirtualMemory.Call(
		uintptr(process),
		baseAddr,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtWriteVirtualMemory: NTSTATUS 0x%08X", uint32(r))
	}
	return written, nil
}

// NtProtectVirtualMemory changes memory protection.
func NtProtectVirtualMemory(process windows.Handle, baseAddr, size uintptr, newProtect uint32) (uint32, error) {
	addr := baseAddr
	regionSize := size
	var oldProtect uint32
	r, _, _ := api.ProcNtProtectVirtualMemory.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%08X", uint32(r))
	}
	return oldProtect, nil
}

// NtCreateThreadEx creates a thread in a process.
func NtCreateThreadEx(process windows.Handle, startAddr, parameter uintptr) (windows.Handle, error) {
	var hThread windows.Handle
	r, _, _ := api.ProcNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		api.ThreadAllAccess,
		0,
		uintptr(process),
		startAddr,
		parameter,
		0, 0, 0, 0, 0,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%08X", uint32(r))
	}
	return hThread, nil
}

// NtQuerySystemInformation queries system information.
func NtQuerySystemInformation(infoClass int32, buf unsafe.Pointer, bufLen uint32) (uint32, error) {
	var retLen uint32
	r, _, _ := api.ProcNtQuerySystemInformation.Call(
		uintptr(infoClass),
		uintptr(buf),
		uintptr(bufLen),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return retLen, fmt.Errorf("NtQuerySystemInformation: NTSTATUS 0x%08X", uint32(r))
	}
	return retLen, nil
}
