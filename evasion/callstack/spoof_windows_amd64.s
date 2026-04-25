// SilentMoonwalk-style stack pivot. Two asm entry points coordinate via
// per-OS-thread global state (caller is responsible for serialization
// via runtime.LockOSThread + a single SpoofCall in flight per goroutine).
//
// spoofPivot — saves Go's RSP/R14, sets RSP to the caller-supplied
// side-stack top, loads Win64 arg regs, and JMPs to target. From the
// CPU's perspective, target is now executing under a fake call site
// whose return chain has been pre-planted on the side stack.
//
// spoofTrampoline — the address Go plants at the chain's bottom slot.
// When target's RET walks the chain to the last entry, that entry's
// value is spoofTrampoline's address; the final RET in the chain
// transfers control here. We capture target's return value (RAX),
// restore Go's RSP/R14, write the value into spoofPivot's return slot
// at the correct stack offset, and RET — popping the original Go
// caller's return address that was on the Go stack at spoofPivot
// entry.

//go:build windows && amd64

#include "textflag.h"

// Per-OS-thread save area. SpoofCall LockOSThreads before calling into
// asm so this state isn't multiplexed across goroutines on the same M.
GLOBL ·savedGoSP(SB), NOPTR, $8
GLOBL ·savedGoG(SB), NOPTR, $8
GLOBL ·savedReturnVal(SB), NOPTR, $8

// func spoofPivot(target, newRSP, a1, a2, a3, a4 uintptr) uintptr
//
// Frame layout (RSP-relative at function entry — Go's CALL pushed an
// 8-byte return address):
//   SP+0   = return address (Go caller of spoofPivot)
//   SP+8   = target            (+0(FP))
//   SP+16  = newRSP            (+8(FP))
//   SP+24  = a1                (+16(FP))
//   SP+32  = a2                (+24(FP))
//   SP+40  = a3                (+32(FP))
//   SP+48  = a4                (+40(FP))
//   SP+56  = ret slot          (+48(FP))
TEXT ·spoofPivot(SB), NOSPLIT, $0-56
    // Stash Go's RSP and g pointer (R14) so spoofTrampoline can restore them.
    MOVQ SP, ·savedGoSP(SB)
    MOVQ R14, ·savedGoG(SB)

    // Load target into R10 (a volatile register Win64 callees may clobber,
    // but we only read it once before the JMP).
    MOVQ target+0(FP), R10

    // Win64 calling convention: first 4 args go in RCX/RDX/R8/R9.
    MOVQ a1+16(FP), CX
    MOVQ a2+24(FP), DX
    MOVQ a3+32(FP), R8
    MOVQ a4+40(FP), R9

    // Pivot to the side stack. Target's RET will pop chain[0] from here.
    MOVQ newRSP+8(FP), SP

    // Win64 ABI requires 32 bytes of shadow space above the args. Allocate
    // it now so target's prologue doesn't trample our chain.
    SUBQ $32, SP

    // Hand off to target. We never return through this path — the chain's
    // last RET transfers control to spoofTrampoline.
    JMP R10

// spoofTrampoline — chain bottom lands here. Restores Go state and
// returns to spoofPivot's caller via the saved Go return address.
TEXT ·spoofTrampoline(SB), NOSPLIT, $0
    // Capture target's return value before we touch any registers that
    // could clobber it.
    MOVQ AX, ·savedReturnVal(SB)

    // Restore Go's RSP and g pointer.
    MOVQ ·savedGoSP(SB), SP
    MOVQ ·savedGoG(SB), R14

    // SP now equals what spoofPivot saw at entry — the Go caller's RET
    // address sits at SP+0, and spoofPivot's ret slot (+48(FP)) sits at
    // SP+56 (8 for the RET addr + 48 for the FP offset).
    MOVQ ·savedReturnVal(SB), AX
    MOVQ AX, 56(SP)

    // RET pops the Go caller's return address and resumes Go.
    RET

// func spoofTrampolineAddr() uintptr
//
// Returns the address of spoofTrampoline so Go code can plant it as
// the chain's bottom slot.
TEXT ·spoofTrampolineAddr(SB), NOSPLIT, $0-8
    LEAQ ·spoofTrampoline(SB), AX
    MOVQ AX, ret+0(FP)
    RET
