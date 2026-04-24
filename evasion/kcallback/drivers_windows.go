//go:build windows && amd64

package kcallback

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SystemModuleInformation = 11 (from the SYSTEM_INFORMATION_CLASS enum).
const systemModuleInformation = 11

// STATUS_INFO_LENGTH_MISMATCH — first call returns this with the
// required buffer length in the ReturnLength out-param.
const statusInfoLengthMismatch = 0xC0000004

// rtlProcessModuleInformation mirrors RTL_PROCESS_MODULE_INFORMATION
// (winternl.h). Packed 296 bytes per entry on x64.
type rtlProcessModuleInformation struct {
	Section          uintptr
	MappedBase       uintptr
	ImageBase        uintptr
	ImageSize        uint32
	Flags            uint32
	LoadOrderIndex   uint16
	InitOrderIndex   uint16
	LoadCount        uint16
	OffsetToFileName uint16
	FullPathName     [256]byte
}

// loadedModule is the decoded form we cache after one
// NtQuerySystemInformation call.
type loadedModule struct {
	Base uintptr
	Size uint32
	Name string // basename only (after OffsetToFileName)
	Path string // full "\\SystemRoot\\..." path
}

var (
	loadedModulesOnce sync.Once
	loadedModules     []loadedModule
	loadedModulesErr  error
)

func ensureLoadedModules() ([]loadedModule, error) {
	loadedModulesOnce.Do(func() {
		loadedModules, loadedModulesErr = fetchLoadedModules()
	})
	return loadedModules, loadedModulesErr
}

func fetchLoadedModules() ([]loadedModule, error) {
	var retLen uint32
	// Probe for the required size.
	r, _, _ := procNtQuerySystemInformation.Call(
		systemModuleInformation, 0, 0,
		uintptr(unsafe.Pointer(&retLen)),
	)
	if uint32(r) != statusInfoLengthMismatch {
		return nil, fmt.Errorf("NtQuerySystemInformation probe: NTSTATUS 0x%X", uint32(r))
	}
	// Pad a bit because the module list can grow between the two calls.
	buf := make([]byte, retLen+0x1000)
	r, _, _ = procNtQuerySystemInformation.Call(
		systemModuleInformation,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return nil, fmt.Errorf("NtQuerySystemInformation fetch: NTSTATUS 0x%X", uint32(r))
	}
	n := *(*uint32)(unsafe.Pointer(&buf[0]))
	entries := unsafe.Slice(
		(*rtlProcessModuleInformation)(unsafe.Pointer(&buf[8])),
		int(n),
	)
	out := make([]loadedModule, 0, n)
	for i := range entries {
		e := &entries[i]
		full := cstrUntilNul(e.FullPathName[:])
		name := full
		if int(e.OffsetToFileName) < len(e.FullPathName) {
			name = cstrUntilNul(e.FullPathName[e.OffsetToFileName:])
		}
		out = append(out, loadedModule{
			Base: e.ImageBase,
			Size: e.ImageSize,
			Name: name,
			Path: full,
		})
	}
	return out, nil
}

// NtoskrnlBase returns the kernel image base via NtQuerySystemInformation
// (SystemModuleInformation). ntoskrnl.exe is always index 0 of the
// returned module list on a booted Windows host.
func NtoskrnlBase() (uintptr, error) {
	mods, err := ensureLoadedModules()
	if err != nil {
		return 0, err
	}
	for _, m := range mods {
		if strings.EqualFold(m.Name, "ntoskrnl.exe") {
			return m.Base, nil
		}
	}
	return 0, ErrNtoskrnlNotFound
}

// DriverAt reports which driver module covers addr, or "" if none.
// Returns ErrNtoskrnlNotFound only if the underlying module list
// couldn't be fetched at all; a missing address returns ("", nil).
func DriverAt(addr uintptr) (string, error) {
	mods, err := ensureLoadedModules()
	if err != nil {
		return "", err
	}
	for _, m := range mods {
		if addr >= m.Base && addr < m.Base+uintptr(m.Size) {
			return m.Name, nil
		}
	}
	return "", nil
}

func cstrUntilNul(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

var (
	modNtdll                     = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = modNtdll.NewProc("NtQuerySystemInformation")
)
