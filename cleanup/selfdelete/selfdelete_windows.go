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

// Note on ADS package: cleanup/selfdelete intentionally does not use system/ads.
// system/ads operates on named streams via CreateFile("path:streamname") — a high-level
// approach for reading/writing ADS content. selfdelete.Run() instead renames the DEFAULT
// stream (:$DATA) to a throwaway name using SetFileInformationByHandle + FILE_RENAME_INFO,
// which is a lower-level operation with no equivalent in system/ads. The two packages are
// complementary, not redundant.

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

// _FILE_DISPOSITION_INFO is the legacy disposition struct
// (FileDispositionInfo class, value 4). Win11 24H2's
// NtfsSetDispositionInfo redirects this to an alternate data stream
// instead of unlinking the file — the rename succeeds, the disposition
// returns success, but the file remains visible. Used as a fallback
// for pre-1709 builds that don't support the Ex form.
type _FILE_DISPOSITION_INFO struct {
	DeleteFile bool
}

// _FILE_DISPOSITION_INFO_EX is the modern disposition struct
// (FileDispositionInfoEx class, value 21; available Win10 1709+).
// Combined with FILE_DISPOSITION_POSIX_SEMANTICS the kernel actually
// unlinks the file even on Win11 24H2 where the legacy class gets
// rerouted into a phantom ADS. See LloydLabs/delete-self-poc and
// tkyn.dev "Deleting yourself in Windows" for the Win11 24H2
// mitigation analysis.
type _FILE_DISPOSITION_INFO_EX struct {
	Flags uint32
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

// dsOpenHandleShared opens a file with DELETE access and FILE_SHARE_DELETE.
// Required for the second open in DeleteFile: after the default :$DATA stream
// is renamed, Windows records an internal reference that prevents exclusive
// disposition unless the caller allows FILE_SHARE_DELETE on reopen.
func dsOpenHandleShared(pwPath *uint16) (windows.Handle, error) {
	return windows.CreateFile(
		pwPath,
		windows.DELETE,
		windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
}

// Pre-computed rename info buffer — the stream name is a compile-time constant.
var dsRenameInfoBuf = func() []byte {
	streamName, _ := windows.UTF16FromString(":deadbeef")
	nameByteLen := uint32(len(streamName)-1) * 2
	headerSize := unsafe.Offsetof(_FILE_RENAME_INFO{}.FileName)
	buf := make([]byte, uintptr(headerSize)+uintptr(nameByteLen))
	*(*uint32)(unsafe.Pointer(&buf[unsafe.Offsetof(_FILE_RENAME_INFO{}.FileNameLength)])) = nameByteLen
	fnOffset := headerSize
	for i := 0; i < len(streamName)-1; i++ {
		*(*uint16)(unsafe.Pointer(&buf[fnOffset+uintptr(i)*2])) = streamName[i]
	}
	return buf
}()

func dsRenameHandle(hHandle windows.Handle) error {
	return windows.SetFileInformationByHandle(
		hHandle,
		windows.FileRenameInfo,
		&dsRenameInfoBuf[0],
		uint32(len(dsRenameInfoBuf)),
	)
}

// dsDisposeHandle marks the file open on hHandle for deletion.
//
// Prefers FileDispositionInfoEx + (DELETE | POSIX_SEMANTICS) — the
// only path that survives Win11 24H2's NtfsSetDispositionInfo ADS
// redirect. POSIX_SEMANTICS tells NTFS to actually unlink the file
// once the last handle closes, even when the legacy disposition
// class would be silently rerouted.
//
// Falls back to the legacy FileDispositionInfo class on builds that
// don't support Ex (pre-Win10 1709 / Server pre-1709 — STATUS_INVALID_INFO_CLASS,
// surfaces as ERROR_INVALID_PARAMETER from SetFileInformationByHandle).
// The fallback is the original ADS-rename pattern that worked on
// every build down to Win 7 SP1.
func dsDisposeHandle(hHandle windows.Handle) error {
	infoEx := _FILE_DISPOSITION_INFO_EX{
		Flags: windows.FILE_DISPOSITION_DELETE | windows.FILE_DISPOSITION_POSIX_SEMANTICS,
	}
	err := windows.SetFileInformationByHandle(
		hHandle,
		windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&infoEx)),
		uint32(unsafe.Sizeof(infoEx)),
	)
	if err == nil {
		return nil
	}
	// ERROR_INVALID_PARAMETER (87) on pre-1709 = info class not
	// recognized. Anything else (sharing violation, access denied)
	// would fail the legacy path too — but try it for parity with
	// the original code path so old-build behavior is unchanged.
	if !errors.Is(err, syscall.Errno(windows.ERROR_INVALID_PARAMETER)) {
		// Different failure mode (sharing, access). Surface the Ex
		// error so operators can debug — the legacy fallback would
		// produce the same NTSTATUS for these.
		return err
	}

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

	hCurrent, err = dsOpenHandleShared(&wcPath[0])
	if err != nil {
		return err
	}
	if hCurrent == windows.InvalidHandle {
		return ErrInvalidHandle
	}

	err = dsDisposeHandle(hCurrent)
	windows.CloseHandle(hCurrent)
	return err
}

// RunForce retries Run multiple times with a delay between attempts.
// Useful when a backup system (e.g., OneDrive) holds a lock on the file.
func RunForce(retry int, duration time.Duration) error {
	var err error
	for i := 0; i < retry; i++ {
		err = Run()
		if err == nil {
			return nil
		}
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ALREADY_EXISTS {
			return nil
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

	tmpFile, err := os.CreateTemp(os.TempDir(), "*.cmd")
	if err != nil {
		return err
	}
	defer tmpFile.Close()

	// The script does three things:
	// 1. Loops until the target executable is deleted
	// 2. Deletes itself (the .cmd file) using its full path
	// 3. Exits
	scriptPath := tmpFile.Name()
	script := fmt.Sprintf(
		`FOR /L %%%%A IN (0) DO ( DEL /Q /F %s "%s" > NUL 2> NUL & IF NOT EXIST "%s" ( DEL /Q /F "%s" > NUL 2> NUL & EXIT ) & TIMEOUT /T 1 /NOBREAK > NUL )`,
		delopt, path, path, scriptPath,
	)

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

// DeleteFile deletes an arbitrary file using the ADS rename technique.
// Unlike Run(), this targets any path rather than the running executable.
func DeleteFile(path string) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	hFile, err := dsOpenHandle(pathPtr)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	if hFile == windows.InvalidHandle {
		return ErrInvalidHandle
	}

	err = dsRenameHandle(hFile)
	windows.CloseHandle(hFile)
	if err != nil {
		return fmt.Errorf("rename stream: %w", err)
	}

	// Reopen with FILE_SHARE_DELETE: after the :$DATA stream is renamed,
	// Windows records an internal reference that blocks exclusive disposition.
	hFile, err = dsOpenHandleShared(pathPtr)
	if err != nil {
		return fmt.Errorf("reopen %s: %w", path, err)
	}
	if hFile == windows.InvalidHandle {
		return ErrInvalidHandle
	}

	err = dsDisposeHandle(hFile)
	windows.CloseHandle(hFile)
	if err != nil {
		return fmt.Errorf("dispose: %w", err)
	}

	return nil
}

// DeleteFileForce retries DeleteFile with delays between attempts.
// Useful when a lock holder (e.g., antivirus, cloud sync) temporarily blocks deletion.
func DeleteFileForce(path string, retry int, duration time.Duration) error {
	var err error
	for i := 0; i < retry; i++ {
		err = DeleteFile(path)
		if err == nil {
			return nil
		}
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.ERROR_ALREADY_EXISTS {
			return nil
		}
		time.Sleep(duration)
	}
	return err
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
