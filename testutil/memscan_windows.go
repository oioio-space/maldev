package testutil

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ScanProcessMemory searches all committed executable pages (PAGE_EXECUTE_READ
// and PAGE_EXECUTE_READWRITE) in the current process for a byte pattern.
// Returns the address of the first match and true, or 0 and false if not found.
//
// This is useful for verifying that injected shellcode landed in memory.
func ScanProcessMemory(pattern []byte) (uintptr, bool) {
	if len(pattern) == 0 {
		return 0, false
	}
	addr := uintptr(0x10000)
	for addr < 0x7FFFFFFEFFFF {
		var mbi windows.MemoryBasicInformation
		if windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)) != nil {
			break
		}
		if mbi.State == windows.MEM_COMMIT && isExecutable(mbi.Protect) && mbi.RegionSize >= uintptr(len(pattern)) {
			region := unsafe.Slice((*byte)(unsafe.Pointer(mbi.BaseAddress)), mbi.RegionSize)
			if idx := findBytes(region, pattern); idx >= 0 {
				return mbi.BaseAddress + uintptr(idx), true
			}
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	return 0, false
}

// ModuleBounds returns the base address and end address (base+size) of a loaded
// module by handle. Useful for verifying whether an address falls inside or
// outside a specific DLL (e.g., checking if a syscall stub is in ntdll).
func ModuleBounds(handle uintptr) (base, end uintptr, err error) {
	var mi windows.ModuleInfo
	err = windows.GetModuleInformation(
		windows.CurrentProcess(),
		windows.Handle(handle),
		&mi,
		uint32(unsafe.Sizeof(mi)),
	)
	if err != nil {
		return 0, 0, err
	}
	return uintptr(mi.BaseOfDll), uintptr(mi.BaseOfDll) + uintptr(mi.SizeOfImage), nil
}

// ScanProcessMemoryFrom is like ScanProcessMemory but starts scanning from
// the given address. This allows iterating through multiple matches by calling
// ScanProcessMemoryFrom(prevMatch+1, pattern) repeatedly.
func ScanProcessMemoryFrom(startAddr uintptr, pattern []byte) (uintptr, bool) {
	if len(pattern) == 0 || startAddr == 0 {
		return 0, false
	}
	addr := startAddr
	for addr < 0x7FFFFFFEFFFF {
		var mbi windows.MemoryBasicInformation
		if windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)) != nil {
			break
		}
		if mbi.State == windows.MEM_COMMIT && isExecutable(mbi.Protect) && mbi.RegionSize >= uintptr(len(pattern)) {
			regionStart := mbi.BaseAddress
			// If startAddr falls inside this region, begin scanning from startAddr.
			scanStart := uintptr(0)
			if startAddr > regionStart {
				scanStart = startAddr - regionStart
			}
			region := unsafe.Slice((*byte)(unsafe.Pointer(regionStart)), mbi.RegionSize)
			if idx := findBytesFrom(region, pattern, int(scanStart)); idx >= 0 {
				return regionStart + uintptr(idx), true
			}
		}
		addr = mbi.BaseAddress + mbi.RegionSize
	}
	return 0, false
}

func isExecutable(protect uint32) bool {
	return protect == windows.PAGE_EXECUTE_READ ||
		protect == windows.PAGE_EXECUTE_READWRITE ||
		protect == windows.PAGE_EXECUTE_WRITECOPY ||
		protect == windows.PAGE_EXECUTE
}

func findBytes(haystack, needle []byte) int {
	return bytes.Index(haystack, needle)
}

func findBytesFrom(haystack, needle []byte, start int) int {
	idx := bytes.Index(haystack[start:], needle)
	if idx < 0 {
		return -1
	}
	return start + idx
}
