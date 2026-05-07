// Package stage1 emits the polymorphic stub the UPX-style packer
// places in a new section of the modified host binary. The stub:
//
//  1. Prologue: CALL+POP+ADD (PIC shellcode idiom) computes the
//     runtime address of the encrypted text section into a
//     callee-saved register (R15). No LEA RIP-relative golang-asm
//     encoding required — this is the standard escape from
//     "we don't have a linker" land. See KNOWN-ISSUES-1e.md §Bug 1.
//
//  2. For each SGN round (rounds[N-1] first, peeling outermost):
//     - MOV cnt = textSize
//     - MOV key = round.Key
//     - MOV src = R15
//     - loop_X: MOVZBQ (src), byte_reg ; subst ; MOVB byte_reg, (src)
//     - ADD src, 1 ; DEC cnt ; JNZ loop_X
//     - Reset src between rounds (re-MOV from R15)
//
//  3. Epilogue: ADD r15, (OEPRVA - TextRVA) ; JMP r15
//
// All addresses derived from R15 — no symbols, no late binding,
// no post-emit patching beyond a single sentinel-replace pass
// (PatchTextDisplacement) on the prologue ADD's imm32.
//
// # Detection level
//
// N/A — the stub itself is generated at pack-time. Per-pack
// uniqueness comes from poly.Engine's SGN randomization (key /
// register / substitution / junk) plus the pack-time random seed.
package stage1
