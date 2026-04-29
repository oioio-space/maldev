//go:build windows

package drive

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// Win32 message + WM_DEVICECHANGE constants. Values from MSDN
// `Dbt.h` and `WinUser.h` — too few to justify a separate
// constants file.
const (
	wmDeviceChange = 0x0219
	wmDestroy      = 0x0002
	wmClose        = 0x0010

	dbtDeviceArrival        = 0x8000
	dbtDeviceRemoveComplete = 0x8004

	// HWND_MESSAGE — message-only window (no surface, no z-order
	// presence). Cast from `(HWND)-3` per MSDN.
	hwndMessage = ^uintptr(2)
)

// wndClassEx mirrors the Win32 WNDCLASSEXW struct (amd64 layout).
// All zero fields are valid; only `cbSize`, `lpfnWndProc`,
// `lpszClassName` are set.
type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  uintptr
	lpszClassName uintptr
	hIconSm       uintptr
}

// msgStruct mirrors the Win32 MSG struct (amd64 layout).
type msgStruct struct {
	hwnd     uintptr
	message  uint32
	_        uint32 // padding
	wParam   uintptr
	lParam   uintptr
	time     uint32
	_        uint32 // padding
	pt       struct{ x, y int32 }
	lPrivate uint32
	_        uint32 // padding (some headers omit this; harmless overshoot)
}

// WatchEvents starts an event-driven watcher backed by a
// message-only window subscribed to `WM_DEVICECHANGE`. A hidden
// HWND is registered on a goroutine pinned to its OS thread —
// mandatory: the Win32 message loop cannot migrate threads.
//
// Each `WM_DEVICECHANGE` with `DBT_DEVICEARRIVAL` or
// `DBT_DEVICEREMOVECOMPLETE` triggers full enumeration via
// `detectChanges`; the resulting Added / Removed events are
// pushed onto the returned channel.
//
// The channel is closed when `w.ctx` is cancelled — the cancel
// posts `WM_CLOSE` to the hidden window so the pump exits cleanly,
// destroys the window, and unregisters the class.
//
// Buffer 0 yields a synchronous channel; consider buffer ≥ 4 for
// burst-friendly consumers (USB hub re-enumeration emits multiple
// `WM_DEVICECHANGE`s in quick succession).
//
// Compared to [Watcher.Watch] (polling) — `WatchEvents` consumes no
// CPU at idle, fires within ~ms of the actual hardware change, and
// requires no `pollInterval` tuning. Trade-off: a hidden window in
// the implant's process. Use `Watch` for headless contexts where a
// message pump is unwelcome.
func (w *Watcher) WatchEvents(buffer int) (<-chan Event, error) {
	if _, err := w.Snapshot(); err != nil {
		return nil, err
	}
	ch := make(chan Event, buffer)
	startup := make(chan error, 1)
	go w.eventPump(ch, startup)
	if err := <-startup; err != nil {
		return nil, err
	}
	return ch, nil
}

// eventPump runs on an OS-thread-locked goroutine. Registers the
// window class, creates a hidden message-only window, runs the
// message loop, tears everything down on ctx cancel.
//
// `startup` lets the caller distinguish "pump never started"
// (RegisterClassExW / CreateWindowExW failure) from a runtime
// failure mid-watch — the former returns from `WatchEvents`
// synchronously; the latter pushes an Event{Err} through `ch`.
func (w *Watcher) eventPump(ch chan<- Event, startup chan<- error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	defer close(ch)

	classNamePtr, err := windows.UTF16PtrFromString("MaldevDriveWatcher")
	if err != nil {
		startup <- fmt.Errorf("recon/drive: event pump utf16 class name: %w", err)
		return
	}

	wndProcCallback := syscall.NewCallback(func(hwnd, msg, wParam, lParam uintptr) uintptr {
		switch uint32(msg) {
		case wmDeviceChange:
			low := uint32(wParam)
			if low == dbtDeviceArrival || low == dbtDeviceRemoveComplete {
				w.detectChanges(ch)
			}
			return 1 // TRUE — accept the change (BROADCAST_QUERY_DENY would be 0x424D / FALSE)
		case wmDestroy:
			api.ProcPostQuitMessage.Call(0)
			return 0
		}
		ret, _, _ := api.ProcDefWindowProcW.Call(hwnd, msg, wParam, lParam)
		return ret
	})

	cls := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   wndProcCallback,
		lpszClassName: uintptr(unsafe.Pointer(classNamePtr)),
	}
	atom, _, regErr := api.ProcRegisterClassExW.Call(uintptr(unsafe.Pointer(&cls)))
	if atom == 0 {
		startup <- fmt.Errorf("recon/drive: event pump RegisterClassExW: %w", regErr)
		return
	}
	defer api.ProcUnregisterClassW.Call(uintptr(unsafe.Pointer(classNamePtr)), 0)

	hwnd, _, createErr := api.ProcCreateWindowExW.Call(
		0, // dwExStyle
		uintptr(unsafe.Pointer(classNamePtr)),
		0,          // lpWindowName
		0,          // dwStyle
		0, 0, 0, 0, // x, y, nWidth, nHeight
		hwndMessage, // hWndParent — message-only window
		0,           // hMenu
		0,           // hInstance
		0,           // lpParam
	)
	if hwnd == 0 {
		startup <- fmt.Errorf("recon/drive: event pump CreateWindowExW: %w", createErr)
		return
	}
	defer api.ProcDestroyWindow.Call(hwnd)

	// Cancellation watcher — posts WM_CLOSE on ctx.Done() so the
	// pump exits through WM_DESTROY → WM_QUIT. The `pumpDone`
	// channel signals normal pump exit so the watcher unblocks
	// and the goroutine doesn't leak on a runaway parent ctx.
	startup <- nil
	pumpDone := make(chan struct{})
	defer close(pumpDone)
	go func() {
		select {
		case <-w.ctx.Done():
			api.ProcPostMessageW.Call(hwnd, wmClose, 0, 0)
		case <-pumpDone:
		}
	}()

	var msg msgStruct
	for {
		r, _, _ := api.ProcGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		switch int32(r) {
		case 0: // WM_QUIT
			return
		case -1: // GetMessage error
			ch <- Event{Err: fmt.Errorf("recon/drive: event pump GetMessageW returned -1")}
			return
		}
		api.ProcDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}
}
