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
	fakeBufferPins = append(fakeBufferPins, fakeW)

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
