//go:build windows

package api

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// Pre-computed ROR13 hash constants for common modules and functions.
// Module hashes use ROR13Module (with null terminator) on the PEB's
// BaseDllName casing (Windows stores module names with their original case).
// Function hashes use ROR13 (without null terminator) on the ASCII export name.
const (
	// Modules (ROR13Module of BaseDllName as stored in PEB)
	HashKernel32 uint32 = 0x50BB715E // "KERNEL32.DLL"
	HashNtdll    uint32 = 0x411677B7 // "ntdll.dll"
	HashAdvapi32 uint32 = 0x9CB9105F // "ADVAPI32.dll"
	HashUser32   uint32 = 0x51319D6F // "USER32.dll"
	HashShell32  uint32 = 0x18D72CAC // "SHELL32.dll"

	// Functions (ROR13 of ASCII export name)
	HashLoadLibraryA           uint32 = 0xEC0E4E8E
	HashGetProcAddress         uint32 = 0x7C0DFCAA
	HashVirtualAlloc           uint32 = 0x91AFCA54
	HashVirtualProtect         uint32 = 0x7946C61B
	HashCreateThread           uint32 = 0xCA2BD06B
	HashNtAllocateVirtualMemory uint32 = 0xD33BCABD
	HashNtProtectVirtualMemory  uint32 = 0x8C394D89
	HashNtCreateThreadEx        uint32 = 0x4D1DEB74
	HashNtWriteVirtualMemory    uint32 = 0xC5108CC2
)

// ResolveByHash resolves a function address by ROR13 hashes of the module
// and function names. No plaintext strings are used — only uint32 hashes.
//
// This walks the PEB's InLoadOrderModuleList to find the target module,
// then parses its PE export directory to find the target function.
//
// Example:
//
//	addr, err := api.ResolveByHash(api.HashKernel32, api.HashLoadLibraryA)
func ResolveByHash(moduleHash, funcHash uint32) (uintptr, error) {
	base, err := ModuleByHash(moduleHash)
	if err != nil {
		return 0, err
	}
	return ExportByHash(base, funcHash)
}

// ModuleByHash finds a loaded module's base address by walking the PEB's
// InLoadOrderModuleList and comparing ROR13Module hashes of each module's
// BaseDllName (UTF-16LE, hashed as raw bytes with null terminator).
func ModuleByHash(hash uint32) (uintptr, error) {
	// TEB → PEB → Ldr → InLoadOrderModuleList
	teb := nativeCurrentTeb()
	peb := *(*uintptr)(unsafe.Pointer(teb + 0x60))            // TEB+0x60 = PEB (x64)
	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))            // PEB+0x18 = PEB_LDR_DATA
	head := ldr + 0x10                                         // PEB_LDR_DATA+0x10 = InLoadOrderModuleList
	first := *(*uintptr)(unsafe.Pointer(head))                 // head.Flink

	for entry := first; entry != head; entry = *(*uintptr)(unsafe.Pointer(entry)) {
		// LDR_DATA_TABLE_ENTRY offsets (x64, InLoadOrderLinks at +0x00):
		//   +0x30 = DllBase
		//   +0x58 = BaseDllName (UNICODE_STRING: Length uint16, MaxLen uint16, pad, Buffer uintptr)
		dllBase := *(*uintptr)(unsafe.Pointer(entry + 0x30))
		nameLen := *(*uint16)(unsafe.Pointer(entry + 0x58))    // UNICODE_STRING.Length (bytes)
		nameBuf := *(*uintptr)(unsafe.Pointer(entry + 0x60))   // UNICODE_STRING.Buffer (x64: +0x58+8)

		if dllBase == 0 || nameLen == 0 || nameBuf == 0 {
			continue
		}

		// Hash the UTF-16LE module name using ROR13 on the low bytes (ASCII chars)
		// with a null terminator appended, matching hash.ROR13Module convention.
		h := ror13Wide(nameBuf, int(nameLen))
		if h == hash {
			return dllBase, nil
		}
	}

	return 0, fmt.Errorf("module hash 0x%08X not found in PEB", hash)
}

// ExportByHash finds a function address in a loaded PE module by walking
// its export directory and comparing ROR13 hashes of export names.
func ExportByHash(moduleBase uintptr, funcHash uint32) (uintptr, error) {
	// Parse PE headers from loaded image (in-memory layout, RVA-based).
	dosHeader := moduleBase
	if *(*uint16)(unsafe.Pointer(dosHeader)) != 0x5A4D { // "MZ"
		return 0, fmt.Errorf("invalid MZ header at 0x%X", moduleBase)
	}
	lfanew := *(*int32)(unsafe.Pointer(dosHeader + 0x3C))
	peHeader := moduleBase + uintptr(lfanew)

	// PE signature (4) + COFF header (20) + optional header starts at +24
	// Export directory is DataDirectory[0] in the optional header.
	// On x64: optional header starts at peHeader+24, DataDirectory at +112 (0x70).
	exportDirRVA := *(*uint32)(unsafe.Pointer(peHeader + 24 + 112))
	if exportDirRVA == 0 {
		return 0, fmt.Errorf("no export directory at module 0x%X", moduleBase)
	}

	exportDir := moduleBase + uintptr(exportDirRVA)

	// IMAGE_EXPORT_DIRECTORY:
	//   +0x18 = NumberOfNames
	//   +0x1C = AddressOfFunctions
	//   +0x20 = AddressOfNames
	//   +0x24 = AddressOfNameOrdinals
	numNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	addrFunctions := moduleBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 0x1C)))
	addrNames := moduleBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 0x20)))
	addrOrdinals := moduleBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 0x24)))

	for i := uint32(0); i < numNames; i++ {
		// Read name RVA and resolve to pointer
		nameRVA := *(*uint32)(unsafe.Pointer(addrNames + uintptr(i)*4))
		namePtr := moduleBase + uintptr(nameRVA)

		// Hash the ASCII export name using ROR13 (no null terminator).
		h := ror13Ascii(namePtr)
		if h == funcHash {
			// Get ordinal index and function RVA
			ordinal := *(*uint16)(unsafe.Pointer(addrOrdinals + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(addrFunctions + uintptr(ordinal)*4))
			return moduleBase + uintptr(funcRVA), nil
		}
	}

	return 0, fmt.Errorf("export hash 0x%08X not found in module 0x%X", funcHash, moduleBase)
}

// ror13Wide computes ROR13 hash of a UTF-16LE buffer (hashing low byte of
// each char) with a null terminator appended. Matches hash.ROR13Module
// for ASCII-compatible module names.
func ror13Wide(buf uintptr, byteLen int) uint32 {
	var h uint32
	charCount := byteLen / 2
	for i := 0; i < charCount; i++ {
		// Read UTF-16LE char, take low byte (ASCII for Latin chars)
		wchar := *(*[2]byte)(unsafe.Pointer(buf + uintptr(i)*2))
		ch := uint32(wchar[0])
		// High-surrogate or non-ASCII chars use the full uint16 value
		if wchar[1] != 0 {
			ch = uint32(binary.LittleEndian.Uint16(wchar[:]))
		}
		h = (h>>13 | h<<19) + ch
	}
	// Null terminator
	h = (h>>13 | h<<19) + 0
	return h
}

// ror13Ascii computes ROR13 hash of a null-terminated ASCII string in memory.
// Matches hash.ROR13 for export names.
func ror13Ascii(ptr uintptr) uint32 {
	var h uint32
	for {
		b := *(*byte)(unsafe.Pointer(ptr))
		if b == 0 {
			break
		}
		h = (h>>13 | h<<19) + uint32(b)
		ptr++
	}
	return h
}

// nativeCurrentTeb returns the address of the current Thread Environment Block.
// On x64 Windows, the TEB is at GS:0x30.
func nativeCurrentTeb() uintptr
