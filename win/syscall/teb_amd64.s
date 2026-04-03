//go:build windows && amd64

#include "textflag.h"

// func currentTeb() uintptr
TEXT ·currentTeb(SB), NOSPLIT, $0-8
    BYTE $0x65; BYTE $0x48; BYTE $0x8B; BYTE $0x04; BYTE $0x25
    BYTE $0x30; BYTE $0x00; BYTE $0x00; BYTE $0x00
    MOVQ AX, ret+0(FP)
    RET
