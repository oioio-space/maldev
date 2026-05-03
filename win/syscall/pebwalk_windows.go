//go:build windows

package syscall

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hashNtdll is the pre-computed ROR13Module hash of "ntdll.dll"
// (PEB stores it in lowercase).
const hashNtdll = 0x411677B7

// pebModuleByHash walks the PEB InLoadOrderModuleList and returns the base
// address of the module whose BaseDllName hashes to the given value.
// Uses the same ROR13Module convention as hash.ROR13Module.
func pebModuleByHash(moduleHash uint32) (uintptr, error) {
	teb := currentTeb()
	peb := *(*uintptr)(unsafe.Pointer(teb + 0x60))
	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))
	head := ldr + 0x10
	first := *(*uintptr)(unsafe.Pointer(head))

	for entry := first; entry != head; entry = *(*uintptr)(unsafe.Pointer(entry)) {
		dllBase := *(*uintptr)(unsafe.Pointer(entry + 0x30))
		nameLen := *(*uint16)(unsafe.Pointer(entry + 0x58))
		nameBuf := *(*uintptr)(unsafe.Pointer(entry + 0x60))

		if dllBase == 0 || nameLen == 0 || nameBuf == 0 {
			continue
		}

		h := pebRor13Wide(nameBuf, int(nameLen))
		if h == moduleHash {
			return dllBase, nil
		}
	}
	return 0, fmt.Errorf("module hash 0x%08X not found in PEB", moduleHash)
}

// pebExportByHash finds a function address in a loaded PE module by hashing
// each export name with the package default (ROR13) and comparing to funcHash.
// Equivalent to pebExportByHashFunc(moduleBase, funcHash, nil).
func pebExportByHash(moduleBase uintptr, funcHash uint32) (uintptr, error) {
	return pebExportByHashFunc(moduleBase, funcHash, nil)
}

// pebModuleByHashFunc is the swappable-hash variant of pebModuleByHash.
// When fn is nil the fast inlined ROR13-on-wide-bytes path runs, identical
// to pebModuleByHash. When fn is supplied, each module's BaseDllName is
// materialised as a lowercase ASCII Go string (PEB always stores names
// lowercased) and passed through fn — letting HashGate eliminate the
// ROR13Module fingerprint constant from binaries that swap to a different
// algorithm via NewHashGateWith.
func pebModuleByHashFunc(target uint32, fn HashFunc) (uintptr, error) {
	if fn == nil {
		return pebModuleByHash(target)
	}
	teb := currentTeb()
	peb := *(*uintptr)(unsafe.Pointer(teb + 0x60))
	ldr := *(*uintptr)(unsafe.Pointer(peb + 0x18))
	head := ldr + 0x10
	first := *(*uintptr)(unsafe.Pointer(head))

	for entry := first; entry != head; entry = *(*uintptr)(unsafe.Pointer(entry)) {
		dllBase := *(*uintptr)(unsafe.Pointer(entry + 0x30))
		nameLen := *(*uint16)(unsafe.Pointer(entry + 0x58))
		nameBuf := *(*uintptr)(unsafe.Pointer(entry + 0x60))

		if dllBase == 0 || nameLen == 0 || nameBuf == 0 {
			continue
		}

		// Wide UTF-16LE → ASCII Go string. Module names in the PEB are
		// always ASCII (DLL filenames), so the low byte of each uint16
		// is the character we want.
		nChars := int(nameLen) / 2
		ascii := make([]byte, nChars)
		for i := 0; i < nChars; i++ {
			ascii[i] = byte(*(*uint16)(unsafe.Pointer(nameBuf + uintptr(i*2))))
		}
		if fn(string(ascii)) == target {
			return dllBase, nil
		}
	}
	return 0, fmt.Errorf("module hash 0x%08X not found in PEB", target)
}

// pebExportByHashFunc is the swappable-hash variant. When fn is nil, the
// hot ROR13 path runs in place and avoids the per-export Go string copy.
// When fn is supplied, each export name is materialised as a Go string and
// passed through fn — letting operators rebuild with a custom hash so the
// well-known ROR13 constants of NT function names no longer fingerprint
// the binary.
func pebExportByHashFunc(moduleBase uintptr, funcHash uint32, fn HashFunc) (uintptr, error) {
	if *(*uint16)(unsafe.Pointer(moduleBase)) != 0x5A4D {
		return 0, fmt.Errorf("invalid MZ at 0x%X", moduleBase)
	}
	lfanew := *(*int32)(unsafe.Pointer(moduleBase + 0x3C))
	peHeader := moduleBase + uintptr(lfanew)
	exportDirRVA := *(*uint32)(unsafe.Pointer(peHeader + 24 + 112))
	if exportDirRVA == 0 {
		return 0, fmt.Errorf("no export directory at 0x%X", moduleBase)
	}

	exportDir := moduleBase + uintptr(exportDirRVA)
	numNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	addrFunctions := moduleBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 0x1C)))
	addrNames := moduleBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 0x20)))
	addrOrdinals := moduleBase + uintptr(*(*uint32)(unsafe.Pointer(exportDir + 0x24)))

	for i := uint32(0); i < numNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(addrNames + uintptr(i)*4))
		namePtr := moduleBase + uintptr(nameRVA)

		var h uint32
		if fn == nil {
			h = pebRor13Ascii(namePtr)
		} else {
			h = fn(windows.BytePtrToString((*byte)(unsafe.Pointer(namePtr))))
		}
		if h == funcHash {
			ordinal := *(*uint16)(unsafe.Pointer(addrOrdinals + uintptr(i)*2))
			funcRVA := *(*uint32)(unsafe.Pointer(addrFunctions + uintptr(ordinal)*4))
			return moduleBase + uintptr(funcRVA), nil
		}
	}
	return 0, fmt.Errorf("export hash 0x%08X not found in module 0x%X", funcHash, moduleBase)
}

// pebRor13Wide hashes a UTF-16LE buffer with ROR13 + null terminator.
func pebRor13Wide(buf uintptr, byteLen int) uint32 {
	var h uint32
	for i := 0; i < byteLen/2; i++ {
		wchar := *(*[2]byte)(unsafe.Pointer(buf + uintptr(i)*2))
		ch := uint32(wchar[0])
		if wchar[1] != 0 {
			ch = uint32(binary.LittleEndian.Uint16(wchar[:]))
		}
		h = (h>>13 | h<<19) + ch
	}
	h = (h>>13 | h<<19) + 0
	return h
}

// pebRor13Ascii hashes a null-terminated ASCII string with ROR13.
func pebRor13Ascii(ptr uintptr) uint32 {
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

// ror13str computes the ROR13 hash of a Go string (no null terminator).
// Same algorithm as hash.ROR13 — inlined to avoid import cycle with win/api.
func ror13str(name string) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h = (h>>13 | h<<19) + uint32(name[i])
	}
	return h
}

// currentTeb returns the TEB address. Implemented in teb_amd64.s.
func currentTeb() uintptr

