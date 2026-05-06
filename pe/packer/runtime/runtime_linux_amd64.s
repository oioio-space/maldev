// Plan 9 amd64 assembly for the Stage C+D Linux loader.
//
// enterEntry swaps RSP to a caller-supplied stack and JMPs to a
// caller-supplied entry point. Used by PreparedImage.Run() after
// the Go-side code has built a kernel-style stack frame
// (argc/argv/envp/auxv) at stackTop.
//
// NOSPLIT|NOFRAME because the Go runtime's stack-growth machinery
// would corrupt our hand-built frame; we never grow the stack
// here, and we never return.
//
// We deliberately do NOT zero or otherwise touch FS. The loaded
// Go binary's _rt0_amd64_linux calls arch_prctl(ARCH_SET_FS,&g0)
// unconditionally before any FS-relative access, so any value
// the parent left in FS is overwritten before it can be read.
// Spec Q3 answer P: in-process JMP, never returns.

#include "textflag.h"

// func enterEntry(entry, stackTop uintptr)
TEXT ·enterEntry(SB), NOSPLIT|NOFRAME, $0-16
	// Order matters: FP is computed relative to SP, so we must
	// read both args before swapping SP. Once SP is overwritten,
	// FP no longer references our caller's frame.
	MOVQ entry+0(FP), AX
	MOVQ stackTop+8(FP), SP
	JMP  AX
