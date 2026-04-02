//go:build windows

package unhook

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// CommonHookedFunctions is the set of ntdll syscall stubs most frequently
// targeted by EDR/AV inline hooks. These are all NT-layer functions that
// perform process, memory, and thread operations — the core primitives used
// by loaders, injectors, and shellcode runners.
var CommonHookedFunctions = []string{
	"NtAllocateVirtualMemory",
	"NtWriteVirtualMemory",
	"NtProtectVirtualMemory",
	"NtCreateThreadEx",
	"NtMapViewOfSection",
	"NtQueueApcThread",
	"NtSetContextThread",
	"NtResumeThread",
	"NtCreateSection",
	"NtOpenProcess",
}

// cleanSyscallPrologue is the canonical x64 syscall stub prologue on unpatched
// Windows ntdll. EDR hooks replace these first bytes with a JMP to a trampoline.
//
//	4C 8B D1  — mov r10, rcx   (preserve first arg per syscall ABI)
//	B8        — mov eax, <id>  (load syscall number)
var cleanSyscallPrologue = [4]byte{0x4C, 0x8B, 0xD1, 0xB8}

// DetectHooked checks each function name in funcNames against the expected
// clean syscall stub prologue. It returns the names of functions whose first
// 4 bytes do NOT match the canonical pattern, indicating an active inline hook.
//
// Example:
//
//	hooked, err := unhook.DetectHooked(unhook.CommonHookedFunctions)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if len(hooked) > 0 {
//	    log.Printf("hooked functions detected: %v", hooked)
//	    // apply unhooking before proceeding
//	}
func DetectHooked(funcNames []string) ([]string, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	var hooked []string

	for _, name := range funcNames {
		proc := ntdll.NewProc(name)
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("find proc %s: %w", name, err)
		}

		var prologue [4]byte
		if err := readPrologue4(proc.Addr(), &prologue); err != nil {
			return nil, fmt.Errorf("read prologue %s: %w", name, err)
		}
		if prologue != cleanSyscallPrologue {
			hooked = append(hooked, name)
		}
	}

	return hooked, nil
}

// IsHooked reports whether a single ntdll function has been inline-hooked.
// It is a convenience wrapper around DetectHooked for single-function checks.
//
// Example:
//
//	if ok, err := unhook.IsHooked("NtAllocateVirtualMemory"); err != nil {
//	    log.Fatal(err)
//	} else if ok {
//	    log.Println("NtAllocateVirtualMemory is hooked — applying ClassicUnhook")
//	    unhook.ClassicUnhook("NtAllocateVirtualMemory")
//	}
func IsHooked(funcName string) (bool, error) {
	hooked, err := DetectHooked([]string{funcName})
	if err != nil {
		return false, err
	}
	return len(hooked) > 0, nil
}

// HookInfo contains per-function hook detection results including the raw
// prologue bytes for manual inspection.
type HookInfo struct {
	// Name is the ntdll export name (e.g., "NtAllocateVirtualMemory").
	Name string

	// Hooked is true if the first 4 bytes do not match the clean syscall stub.
	Hooked bool

	// Prologue holds the first 8 bytes of the function as observed in memory.
	// Compare against cleanSyscallPrologue to see what the hook looks like.
	Prologue [8]byte
}

// Inspect returns detailed hook status for each function in funcNames.
// Unlike DetectHooked, it returns a result entry for every function (hooked or not)
// along with the raw prologue bytes — useful for logging, debugging, or
// conditional unhooking strategies.
//
// Example:
//
//	infos, err := unhook.Inspect(unhook.CommonHookedFunctions)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, info := range infos {
//	    if info.Hooked {
//	        log.Printf("%s hooked — prologue: % X", info.Name, info.Prologue)
//	    }
//	}
func Inspect(funcNames []string) ([]HookInfo, error) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	results := make([]HookInfo, 0, len(funcNames))

	for _, name := range funcNames {
		proc := ntdll.NewProc(name)
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("find proc %s: %w", name, err)
		}

		var prologue [8]byte
		if err := readPrologue8(proc.Addr(), &prologue); err != nil {
			return nil, fmt.Errorf("read prologue %s: %w", name, err)
		}
		hooked := [4]byte(prologue[:4]) != cleanSyscallPrologue

		results = append(results, HookInfo{
			Name:     name,
			Hooked:   hooked,
			Prologue: prologue,
		})
	}

	return results, nil
}

// readPrologue4 reads 4 bytes from addr in the current process using
// ReadProcessMemory, avoiding direct unsafe.Pointer(uintptr) conversions
// that would be flagged by go vet.
func readPrologue4(addr uintptr, out *[4]byte) error {
	self, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	var n uintptr
	return windows.ReadProcessMemory(self, addr, &out[0], 4, &n)
}

// readPrologue8 reads 8 bytes from addr in the current process using
// ReadProcessMemory.
func readPrologue8(addr uintptr, out *[8]byte) error {
	self, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	var n uintptr
	return windows.ReadProcessMemory(self, addr, &out[0], 8, &n)
}
