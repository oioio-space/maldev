//go:build windows && amd64

#include "textflag.h"

// func nativeCurrentTeb() uintptr
//
// Reads the Thread Environment Block address from the GS segment register.
// On x64 Windows, GS:0x30 contains the linear address of the TEB.
// The BYTE prefix encodes: 65 48 8B 04 25 30 00 00 00 = mov rax, gs:[0x30]
TEXT ·nativeCurrentTeb(SB), NOSPLIT, $0-8
    BYTE $0x65; BYTE $0x48; BYTE $0x8B; BYTE $0x04; BYTE $0x25
    BYTE $0x30; BYTE $0x00; BYTE $0x00; BYTE $0x00
    MOVQ AX, ret+0(FP)
    RET
