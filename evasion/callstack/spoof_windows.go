//go:build windows && amd64

package callstack

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrEmptyChain is returned by SpoofCall when chain has zero frames —
// the spoof relies on at least one fake frame to plant beneath the
// target's call site, otherwise the walker just sees the target's own
// caller.
var ErrEmptyChain = errors.New("callstack: empty spoof chain")

// ErrTooManyArgs is returned by SpoofCall when args has more than 4
// elements. The pivot only sets RCX/RDX/R8/R9 (Win64 first-four args)
// — extending to stack-passed args would need additional asm.
var ErrTooManyArgs = errors.New("callstack: SpoofCall accepts at most 4 args (Win64 RCX/RDX/R8/R9)")

const sideStackBytes = 64 * 1024

// EXPERIMENTAL — the asm pivot landed as v0.16.1 scaffold but its
// end-to-end execution path is fragile in Go's M:N runtime. The
// 6 caller-side unit tests below exercise validation, allocation,
// and trampoline-symbol linkage, but the actual JMP-driven RET-walk
// from a real Win64 leaf (GetCurrentThreadId) into spoofTrampoline
// crashes with an unhandled exception caught by Go's
// lastcontinuehandler — likely from R14 (g-pointer) clobber across
// the pivot, stack-alignment skew on odd-length chains, or SEH chain
// invalidation. Real-target use is gated behind MALDEV_SPOOFCALL_E2E=1.
// The asm + Go layer ship together so future debug iterations have a
// stable starting point; promotion to a tagged release waits on the
// e2e crash being root-caused.
//
// SpoofCall calls target through a synthesized return chain so any
// stack walker that captures the call site mid-execution sees the
// chain frames in place of the real caller. The pivot:
//
//  1. Locks the goroutine to its OS thread (the Go runtime can't
//     migrate a goroutine away while RSP points at a non-Go stack).
//  2. Allocates a 64 KiB side stack via VirtualAlloc.
//  3. Plants the chain frames at the top, with a trampoline back to
//     Go at the bottom.
//  4. JMPs to target with RSP set to the chain's innermost frame.
//  5. Target's `ret` walks the chain (each frame is a lone-RET
//     gadget), eventually lands on the trampoline which restores
//     Go's RSP and returns.
//
// args supplies the target's first four arguments through the Win64
// register convention (RCX/RDX/R8/R9). Targets that need more than
// four arguments are not yet supported.
//
// SpoofCall returns target's RAX (truncated to uintptr). Errors
// indicate validation failures BEFORE the pivot — once the asm runs,
// any failure manifests as a process crash.
//
// Constraints:
//
//   - target MUST be a leaf function that does not call back into Go
//     (no go callbacks, no Go runtime entry points). kernel32!Sleep,
//     OutputDebugStringW, and the like are safe; Go callbacks will
//     crash because R14 (g pointer) is preserved across the pivot but
//     Go runtime checks may misbehave.
//   - target MUST NOT trigger a Windows exception that the runtime
//     would catch — the synthesized stack lacks Go's stack guard
//     pages so Go's exception handler chain cannot run.
//   - chain[i].ReturnAddress MUST be a lone-RET gadget address (e.g.
//     FindReturnGadget()'s result) — NOT a function entry point.
//     When target's RET pops chain[0] the CPU jumps there and
//     immediately RETs, popping chain[1] etc. Planting a function
//     entry (e.g. BaseThreadInitThunk's first byte) will run that
//     function's prologue and the chain unwind breaks.
//
// The chain serves two purposes simultaneously:
//
//   - Walking: a stack walker (RtlVirtualUnwind / CaptureStackBackTrace)
//     looks up each entry's RUNTIME_FUNCTION; the gadget address must
//     fall inside a registered .pdata range (every byte of ntdll/.text
//     does, so any FindReturnGadget result works).
//   - Execution: the chain self-unwinds via successive RETs.
//
// To synthesize a "BaseThreadInitThunk → RtlUserThreadStart" walk
// illusion, callers must locate lone-RET gadgets WITHIN those
// specific functions' bodies — `StandardChain` returns the function
// entry points (suitable for walking-only consumers like ETW
// inspection) but is NOT directly suitable for SpoofCall.
func SpoofCall(target unsafe.Pointer, chain []Frame, args ...uintptr) (uintptr, error) {
	if target == nil {
		return 0, errors.New("callstack: nil target")
	}
	if len(chain) == 0 {
		return 0, ErrEmptyChain
	}
	if err := Validate(chain); err != nil {
		return 0, err
	}
	if len(args) > 4 {
		return 0, ErrTooManyArgs
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	side, err := allocSideStack(sideStackBytes)
	if err != nil {
		return 0, fmt.Errorf("alloc side stack: %w", err)
	}
	defer freeSideStack(side, sideStackBytes)

	// Side stack grows toward lower addresses on x64. Lay out from the
	// top down: the trampoline address sits at the highest position so
	// the last RET in the chain pops it; chain[0] sits closest to the
	// pivot point so target's RET pops chain[0] first.
	top := side + sideStackBytes
	put := func(slot int, v uintptr) {
		*(*uintptr)(unsafe.Pointer(top - uintptr(8*slot))) = v
	}
	// slot 1 (top) = trampoline
	put(1, trampolineAddr())
	// slots 2..N+1 = chain[N-1], chain[N-2], ..., chain[0]
	// so that target's RET pops chain[0], chain[0]'s RET pops chain[1], etc.
	for i, f := range chain {
		put(2+i, f.ReturnAddress)
	}
	// RSP after pivot points at chain[0] (slot N+1 from the top).
	rsp := top - uintptr(8*(1+len(chain)))

	var a [4]uintptr
	copy(a[:], args)

	return spoofPivot(uintptr(target), rsp, a[0], a[1], a[2], a[3]), nil
}

// allocSideStack reserves an RW region for the synthesized stack. We
// don't request execute permissions — only fake-RA bytes live here
// and the CPU only reads them through RET pops, never executes them
// directly.
func allocSideStack(size int) (uintptr, error) {
	addr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return 0, err
	}
	return addr, nil
}

func freeSideStack(addr uintptr, size int) {
	_ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

// spoofPivot is implemented in spoof_windows_amd64.s. It pivots RSP
// to newRSP, loads RCX/RDX/R8/R9 from a1..a4, and JMPs to target.
// Control returns via the trampoline — see the asm for the full path.
//
//go:noescape
func spoofPivot(target, newRSP, a1, a2, a3, a4 uintptr) uintptr

// trampolineAddr returns the address of the spoofTrampoline asm
// symbol. The chain's last RET pops this address so the trampoline
// runs after target finishes walking the chain.
func trampolineAddr() uintptr {
	return spoofTrampolineAddr()
}

// spoofTrampolineAddr is implemented in asm; it returns the address
// of the trampoline so we can plant it as a return target.
//
//go:noescape
func spoofTrampolineAddr() uintptr
