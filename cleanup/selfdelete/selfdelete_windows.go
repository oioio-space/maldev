//go:build windows

// Package selfdelete provides self-deletion techniques for running executables.
package selfdelete

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrInvalidHandle is returned when a file handle is invalid.
var ErrInvalidHandle = errors.New("invalid handle")

// _FILE_RENAME_INFO matches the Windows FILE_RENAME_INFO layout on x64:
//
//	offset 0:  Flags (uint32, union of ReplaceIfExists/Flags)
//	offset 4:  [4 bytes padding for Handle alignment]
//	offset 8:  RootDirectory (Handle, 8 bytes on x64)
//	offset 16: FileNameLength (uint32)
//	offset 20: FileName (variable-length uint16 array)
type _FILE_RENAME_INFO struct {
	Flags          uint32
	_              uint32         // padding for Handle alignment
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// _FILE_DISPOSITION_INFO is used for file deletion operations.
type _FILE_DISPOSITION_INFO struct {
	DeleteFile bool
}

func dsOpenHandle(pwPath *uint16) (windows.Handle, error) {
	return windows.CreateFile(
		pwPath,
		windows.DELETE,
		0, nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
}

func dsRenameHandle(hHandle windows.Handle) error {
	dsStreamRename, err := windows.UTF16FromString(":deadbeef")
	if err != nil {
		return err
	}

	// UTF-16 byte length of the stream name (excluding null terminator).
	nameByteLen := uint32(len(dsStreamRename)-1) * 2

	// Allocate a buffer large enough for the struct header + full filename.
	headerSize := unsafe.Offsetof(_FILE_RENAME_INFO{}.FileName)
	buf := make([]byte, uintptr(headerSize)+uintptr(nameByteLen))

	// Fill the header fields at the start of the buffer.
	// Flags = 0 (offset 0), RootDirectory = 0 (offset 8),
	// FileNameLength at offset 16.
	*(*uint32)(unsafe.Pointer(&buf[unsafe.Offsetof(_FILE_RENAME_INFO{}.FileNameLength)])) = nameByteLen

	// Copy the UTF-16 stream name into the FileName field.
	fnOffset := headerSize
	for i := 0; i < len(dsStreamRename)-1; i++ {
		*(*uint16)(unsafe.Pointer(&buf[fnOffset+uintptr(i)*2])) = dsStreamRename[i]
	}

	return windows.SetFileInformationByHandle(
		hHandle,
		windows.FileRenameInfo,
		&buf[0],
		uint32(len(buf)),
	)
}

func dsDepositeHandle(hHandle windows.Handle) error {
	var fDelete _FILE_DISPOSITION_INFO
	fDelete.DeleteFile = true

	return windows.SetFileInformationByHandle(
		hHandle,
		windows.FileDispositionInfo,
		(*byte)(unsafe.Pointer(&fDelete)),
		uint32(unsafe.Sizeof(fDelete)),
	)
}

// Run performs self-deletion using NTFS alternate data streams.
// 1. Opens the file handle with DELETE permission.
// 2. Renames the unnamed :$DATA stream to ":deadbeef".
// 3. Marks the file for deletion.
// 4. Closes the handle.
func Run() error {
	var wcPath [windows.MAX_PATH + 1]uint16

	_, err := windows.GetModuleFileName(0, &wcPath[0], windows.MAX_PATH)
	if err != nil {
		return err
	}

	hCurrent, err := dsOpenHandle(&wcPath[0])
	if err != nil {
		return err
	}
	if hCurrent == windows.InvalidHandle {
		return ErrInvalidHandle
	}

	err = dsRenameHandle(hCurrent)
	windows.CloseHandle(hCurrent)
	if err != nil {
		return err
	}

	hCurrent, err = dsOpenHandle(&wcPath[0])
	if err != nil {
		return err
	}
	if hCurrent == windows.InvalidHandle {
		return ErrInvalidHandle
	}

	err = dsDepositeHandle(hCurrent)
	windows.CloseHandle(hCurrent)
	return err
}

// RunForce retries Run multiple times with a delay between attempts.
// Useful when a backup system (e.g., OneDrive) holds a lock on the file.
func RunForce(retry int, duration time.Duration) error {
	var err error

loop:
	for i := 0; i < retry; i++ {
		err = Run()
		if err == nil {
			break loop
		}
		if errno, ok := err.(syscall.Errno); ok {
			if errno == syscall.ERROR_ALREADY_EXISTS {
				err = nil
				break loop
			}
		}
		time.Sleep(duration)
	}

	return err
}

// RunWithScript performs self-deletion using a batch script that loops
// until the executable terminates, then deletes it.
func RunWithScript(wait time.Duration) error {
	path, err := os.Executable()
	if err != nil {
		return err
	}

	var delopt string
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	fileAttrs := fileInfo.Sys().(*syscall.Win32FileAttributeData)
	if fileAttrs.FileAttributes&syscall.FILE_ATTRIBUTE_HIDDEN != 0 {
		delopt = "/AH"
	}

	script := fmt.Sprintf(
		`DEL %%~nx0 > NUL 2> NUL & FOR /L %%%%A IN (0) DO ( DEL /Q /F %s "%s" > NUL 2> NUL & TIMEOUT /T 1 /NOBREAK & IF NOT EXIST "%s" ( EXIT ) )`,
		delopt, path, path,
	)

	tmpFile, err := os.CreateTemp(os.TempDir(), "*.cmd")
	if err != nil {
		return err
	}
	defer tmpFile.Close()

	if _, err = tmpFile.WriteString(script); err != nil {
		return err
	}

	cmd, err := exec.LookPath("cmd")
	if err != nil {
		return err
	}

	handler := exec.Command(cmd, "/c", tmpFile.Name())
	handler.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err = handler.Start(); err != nil {
		return err
	}

	time.Sleep(wait)
	return nil
}

// MarkForDeletion marks the executable for deletion at next reboot.
// Requires administrator privileges.
func MarkForDeletion() error {
	path, err := os.Executable()
	if err != nil {
		return err
	}

	pathUTF16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}

	return windows.MoveFileEx(pathUTF16, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
