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

	"github.com/oioio-space/maldev/win/api"
)

// ErrInvalidHandle is returned when a file handle is invalid.
var ErrInvalidHandle = errors.New("invalid handle")

// _FILE_RENAME_INFO is used for file rename operations.
type _FILE_RENAME_INFO struct {
	Union struct {
		ReplaceIfExists bool
		Flags           uint32
	}
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
	var fRename _FILE_RENAME_INFO

	dsStreamRename, err := windows.UTF16FromString(":deadbeef")
	if err != nil {
		return err
	}

	lpwStream := &dsStreamRename[0]

	fRename.FileNameLength = uint32(unsafe.Sizeof(lpwStream))

	api.ProcRtlCopyMemory.Call(
		uintptr(unsafe.Pointer(&fRename.FileName[0])),
		uintptr(unsafe.Pointer(lpwStream)),
		unsafe.Sizeof(lpwStream),
	)

	return windows.SetFileInformationByHandle(
		hHandle,
		windows.FileRenameInfo,
		(*byte)(unsafe.Pointer(&fRename)),
		uint32(unsafe.Sizeof(fRename)+unsafe.Sizeof(lpwStream)),
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
		"DEL %%~nx0 > NUL 2> NUL & FOR /L %%%%A IN (0) DO ( DEL /Q /F %s %s > NUL 2> NUL & TIMEOUT /T 1 /NOBREAK & IF NOT EXIST %s ( EXIT ) )",
		delopt, path, path,
	)

	tmpFile, err := os.CreateTemp(os.TempDir(), "*.cmd")
	if err != nil {
		return err
	}
	defer tmpFile.Close()
	defer os.Remove(tmpFile.Name())

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
