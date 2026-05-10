package packer

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// bundleStubVendorAwareV2 is the Builder-driven equivalent of the
// hand-encoded [bundleStubVendorAware]. Phase 2 of the bundle-stub
// migration per docs/superpowers/specs/2026-05-10-bundle-stub-builder-migration-audit.md.
//
// Why a V2 alongside V1:
//
//   - V1's hand-encoded bytes have proven correctness (years of
//     Linux runtime tests green) but every Jcc displacement is a
//     manual count — adding §5 negate-flag or §4 PHASE-B-2 PT_WIN_BUILD
//     means recomputing 10+ displacements by hand.
//   - V2 expresses every jump via [amd64.Builder] labels. The
//     assembler resolves displacements automatically. §5 + §4-B-2
//     become structural changes (insert instructions) instead of
//     byte-recompute exercises.
//
// V2 is meant to be functionally equivalent to V1, NOT byte-identical.
// golang-asm picks valid encodings that may differ from the hand-
// chosen V1 bytes (e.g. `mov rdi, rsp` can be 48 89 e7 or 48 8b fc).
// Functional equivalence is validated by running the same wrap
// pipeline through the existing TestWrapBundleAsExecutableLinux_*
// runtime tests; if a Linux exit-42 bundle works under V2, the
// emission is correct.
//
// Layout follows the audit's section-by-section table. Labels
// resolved by Builder: `.loop`, `.matched`, `.no_match`, `.next`,
// `.vendor_zero_check`, `.dec`, `.jmp_payload`.
//
// Returns the assembled stub bytes plus the byte offset where the
// `add r15, imm32` immediate sits (caller patches it post-encode
// with the bundle offset). For V1 this is the constant
// [bundleOffsetImm32Pos] = 10; V2 returns it explicitly because the
// PIC trampoline's RawBytes block is at a known fixed prefix.
func bundleStubVendorAwareV2() ([]byte, int, error) {
	b, err := amd64.New()
	if err != nil {
		return nil, 0, fmt.Errorf("packer: amd64 builder: %w", err)
	}

	// ── Section 1: PIC trampoline (14 B, all RawBytes) ────────────────
	// call .pic     ; e8 00 00 00 00 — call to next instruction
	// pop  r15      ; 41 5f
	// add  r15, imm32 ; 49 81 c7 XX XX XX XX (imm patched at wrap time)
	// The call+pop+add idiom is awkward via Builder labels (the call
	// would target the very next instruction's label); RawBytes is
	// cleaner and matches V1 byte-for-byte.
	if err := b.RawBytes([]byte{
		0xe8, 0x00, 0x00, 0x00, 0x00, // call .pic
		0x41, 0x5f, // pop r15
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00, // add r15, imm32 (patched)
	}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 PIC: %w", err)
	}
	immPos := 10 // byte offset of the imm32 within the emitted stream

	// ── Section 2: CPUID prologue (22 B) ──────────────────────────────
	// sub  rsp, 0x10
	// mov  rdi, rsp
	// xor  eax, eax
	// cpuid
	// mov  [rdi], ebx
	// mov  [rdi+4], edx
	// mov  [rdi+8], ecx
	// mov  rsi, rdi
	if err := b.SUB(amd64.RSP, amd64.Imm(16)); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 sub rsp: %w", err)
	}
	if err := b.MOV(amd64.RDI, amd64.RSP); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov rdi, rsp: %w", err)
	}
	if err := b.XOR(amd64.RAX, amd64.RAX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 xor eax, eax: %w", err)
	}
	if err := b.RawBytes([]byte{0x0f, 0xa2}); err != nil { // cpuid
		return nil, 0, fmt.Errorf("packer: V2 cpuid: %w", err)
	}
	if err := b.MOVL(amd64.MemOp{Base: amd64.RDI}, amd64.RBX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov [rdi], ebx: %w", err)
	}
	if err := b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 4}, amd64.RDX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov [rdi+4], edx: %w", err)
	}
	if err := b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 8}, amd64.RCX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov [rdi+8], ecx: %w", err)
	}
	if err := b.MOV(amd64.RSI, amd64.RDI); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov rsi, rdi: %w", err)
	}

	// ── Section 3: Loop setup (14 B) ──────────────────────────────────
	// movzx ecx, word [r15+6]
	// mov   r8d,        [r15+8]
	// add   r8, r15
	// xor   eax, eax
	if err := b.MOVZWL(amd64.RCX, amd64.MemOp{Base: amd64.R15, Disp: 6}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 movzx ecx: %w", err)
	}
	if err := b.MOVL(amd64.R8, amd64.MemOp{Base: amd64.R15, Disp: 8}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov r8d: %w", err)
	}
	if err := b.ADD(amd64.R8, amd64.R15); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 add r8, r15: %w", err)
	}
	if err := b.XOR(amd64.RAX, amd64.RAX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 xor eax, eax (loop): %w", err)
	}

	// ── Section 4: Loop body (~65 B) ──────────────────────────────────
	// Labels participate in displacement resolution.
	loopLabel := b.Label("loop")
	matchedLabel := amd64.LabelRef("matched")
	noMatchLabel := amd64.LabelRef("no_match")
	nextLabel := amd64.LabelRef("next")
	vendorZeroCheckLabel := amd64.LabelRef("vendor_zero_check")

	// cmp eax, ecx
	if err := b.CMP(amd64.RAX, amd64.RCX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 cmp eax, ecx: %w", err)
	}
	// jge .no_match
	if err := b.JGE(noMatchLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 jge no_match: %w", err)
	}
	// movzx r9d, byte [r8]
	if err := b.MOVZX(amd64.R9, amd64.MemOp{Base: amd64.R8}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 movzx r9d: %w", err)
	}
	// test r9b, 8                  — RawBytes (Plan 9 quirk on TEST r/m,imm)
	if err := b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x08}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 test r9b 8: %w", err)
	}
	// jnz .matched
	if err := b.JNZ(matchedLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 jnz matched: %w", err)
	}
	// test r9b, 1                  — RawBytes
	if err := b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x01}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 test r9b 1: %w", err)
	}
	// jz .next
	if err := b.JE(nextLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 jz next: %w", err)
	}
	// mov r10, [r8+4]
	if err := b.MOV(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 4}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov r10: %w", err)
	}
	// cmp r10, [rsi]
	if err := b.CMP(amd64.R10, amd64.MemOp{Base: amd64.RSI}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 cmp r10 [rsi]: %w", err)
	}
	// jne .vendor_zero_check
	if err := b.JNZ(vendorZeroCheckLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 jne vendor_zero_check: %w", err)
	}
	// mov r10d, [r8+12]
	if err := b.MOVL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 12}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 mov r10d: %w", err)
	}
	// cmp r10d, [rsi+8]
	if err := b.CMPL(amd64.R10, amd64.MemOp{Base: amd64.RSI, Disp: 8}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 cmpl r10d: %w", err)
	}
	// je .matched
	if err := b.JE(matchedLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 je matched: %w", err)
	}

	// .vendor_zero_check
	b.Label("vendor_zero_check")
	// mov r10, [r8+4]
	if err := b.MOV(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 4}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 vzc mov r10: %w", err)
	}
	// test r10, r10
	if err := b.TEST(amd64.R10, amd64.R10); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 vzc test r10: %w", err)
	}
	// jnz .next
	if err := b.JNZ(nextLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 vzc jnz next: %w", err)
	}
	// mov r10d, [r8+12]
	if err := b.MOVL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 12}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 vzc mov r10d: %w", err)
	}
	// test r10d, r10d              — Builder TEST with 32-bit operands;
	// uses TESTQ but functionally identical because TEST sets flags on
	// AND result, and zero-AND-zero is zero either way.
	if err := b.TEST(amd64.R10, amd64.R10); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 vzc test r10d: %w", err)
	}
	// jz .matched
	if err := b.JE(matchedLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 vzc jz matched: %w", err)
	}

	// .next
	b.Label("next")
	// add r8, 48
	if err := b.ADD(amd64.R8, amd64.Imm(48)); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 next add r8: %w", err)
	}
	// inc eax
	if err := b.INC(amd64.RAX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 next inc eax: %w", err)
	}
	// jmp .loop
	if err := b.JMP(loopLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 next jmp loop: %w", err)
	}

	// ── Section 5: .no_match — Linux sys_exit_group(0) (9 B) ──────────
	b.Label("no_match")
	// mov eax, 231
	if err := b.MOVL(amd64.RAX, amd64.Imm(231)); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 no_match mov eax: %w", err)
	}
	// xor edi, edi
	if err := b.XOR(amd64.RDI, amd64.RDI); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 no_match xor edi: %w", err)
	}
	// syscall
	if err := b.SYSCALL(); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 no_match syscall: %w", err)
	}

	// ── Section 6: .matched + decrypt + JMP (~72 B) ───────────────────
	b.Label("matched")
	// mov r9d, [r15+12]
	if err := b.MOVL(amd64.R9, amd64.MemOp{Base: amd64.R15, Disp: 12}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 matched mov r9d: %w", err)
	}
	// mov r10d, eax
	if err := b.MOVL(amd64.R10, amd64.RAX); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 matched mov r10d: %w", err)
	}
	// shl r10d, 5
	if err := b.SHL(amd64.R10, amd64.Imm(5)); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 matched shl: %w", err)
	}
	// add r9d, r10d
	if err := b.ADD(amd64.R9, amd64.R10); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 matched add: %w", err)
	}
	// add r9, r15
	if err := b.ADD(amd64.R9, amd64.R15); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 matched add r9 r15: %w", err)
	}
	// mov rcx, r9
	if err := b.MOV(amd64.RCX, amd64.R9); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 matched mov rcx: %w", err)
	}

	// Decrypt loop:
	// mov edi, [rcx]
	if err := b.MOVL(amd64.RDI, amd64.MemOp{Base: amd64.RCX}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec mov edi: %w", err)
	}
	// add rdi, r15
	if err := b.ADD(amd64.RDI, amd64.R15); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec add rdi: %w", err)
	}
	// mov esi, [rcx+4]
	if err := b.MOVL(amd64.RSI, amd64.MemOp{Base: amd64.RCX, Disp: 4}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec mov esi: %w", err)
	}
	// lea r8, [rcx+16]
	if err := b.LEA(amd64.R8, amd64.MemOp{Base: amd64.RCX, Disp: 16}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec lea r8: %w", err)
	}
	// xor r9d, r9d
	if err := b.XOR(amd64.R9, amd64.R9); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec xor r9d: %w", err)
	}

	decLabel := b.Label("dec")
	jmpPayloadLabel := amd64.LabelRef("jmp_payload")
	// test esi, esi
	if err := b.TEST(amd64.RSI, amd64.RSI); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec test esi: %w", err)
	}
	// jz .jmp_payload
	if err := b.JE(jmpPayloadLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec jz jmp_payload: %w", err)
	}
	// 8-bit per-byte XOR loop body — RawBytes for Plan-9-tricky
	// 8-bit ops:
	//   mov   al, [rdi]          ; 8a 07
	//   mov   dl, r9b            ; 44 88 ca
	//   and   dl, 15             ; 80 e2 0f
	//   movzx edx, dl            ; 0f b6 d2
	//   xor   al, [r8+rdx]       ; 41 32 04 10
	//   mov   [rdi], al          ; 88 07
	if err := b.RawBytes([]byte{
		0x8a, 0x07, // mov al, [rdi]
		0x44, 0x88, 0xca, // mov dl, r9b
		0x80, 0xe2, 0x0f, // and dl, 15
		0x0f, 0xb6, 0xd2, // movzx edx, dl
		0x41, 0x32, 0x04, 0x10, // xor al, [r8+rdx]
		0x88, 0x07, // mov [rdi], al
	}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec 8-bit ops: %w", err)
	}
	// inc rdi
	if err := b.INC(amd64.RDI); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec inc rdi: %w", err)
	}
	// inc r9d
	if err := b.INC(amd64.R9); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec inc r9d: %w", err)
	}
	// dec esi
	if err := b.DEC(amd64.RSI); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec dec esi: %w", err)
	}
	// jmp .dec
	if err := b.JMP(decLabel); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 dec jmp dec: %w", err)
	}

	b.Label("jmp_payload")
	// mov edi, [rcx]
	if err := b.MOVL(amd64.RDI, amd64.MemOp{Base: amd64.RCX}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 jp mov edi: %w", err)
	}
	// add rdi, r15
	if err := b.ADD(amd64.RDI, amd64.R15); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 jp add rdi: %w", err)
	}
	// jmp rdi
	if err := b.JMPReg(amd64.RDI); err != nil {
		return nil, 0, fmt.Errorf("packer: V2 jp jmp rdi: %w", err)
	}

	out, err := b.Encode()
	if err != nil {
		return nil, 0, fmt.Errorf("packer: V2 encode: %w", err)
	}
	return out, immPos, nil
}
