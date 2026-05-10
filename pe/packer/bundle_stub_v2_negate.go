package packer

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// bundleStubVendorAwareV2Negate is the Phase 4a iteration of V2 —
// adds §5 negate-flag support per
// docs/superpowers/specs/2026-05-10-bundle-stub-negate-and-winbuild.md.
//
// Restructures the per-entry test to compute the match outcome
// into AL (1 = match, 0 = no match), XOR with the entry's negate
// byte, then branch on the result. This makes the FingerprintEntry's
// negate field operationally meaningful — a per-entry "match the
// EXCEPT this" semantic.
//
// Wire-format compatibility: pre-v0.88 entries shipped with the
// negate byte = 0 (FingerprintPredicate.Negate = false). XOR with
// 0 is a no-op, so existing bundles continue to work without
// re-packing.
//
// Layout vs V2 (no negate):
//
//   - V2: per-entry test branches DIRECTLY to .matched on success
//     or .next on failure.
//   - V2-Negate: per-entry test computes AL = 1/0, then a shared
//     `.entry_done` block reads the negate byte, XORs AL, and
//     branches on the final result.
//
// Builder labels: `.loop`, `.matched`, `.no_match`, `.next`,
// `.skip_vendor`, `.vendor_low_mismatch`, `.vendor_fail`,
// `.entry_done`, `.dec`, `.jmp_payload`. Builder resolves all
// rel8/rel32 displacements automatically — the entire +20 bytes of
// new asm is a structural change, not a recompute exercise.
//
// Phase 4b (§4-PHASE-B-2 PT_WIN_BUILD) will plug in BETWEEN
// `.skip_vendor` and `.entry_done` as another bit-check + range
// compare. Today's stub is Linux-only (uses sys_exit_group(0) for
// .no_match); the Windows variant inherits via the existing
// bundleStubVendorAwareWindows patcher.
func bundleStubVendorAwareV2Negate() ([]byte, int, error) {
	b, err := amd64.New()
	if err != nil {
		return nil, 0, fmt.Errorf("packer: amd64 builder: %w", err)
	}

	// === Section 1: PIC trampoline (verbatim from V2) ===
	if err := b.RawBytes([]byte{
		0xe8, 0x00, 0x00, 0x00, 0x00, // call .pic
		0x41, 0x5f, // pop r15
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00, // add r15, imm32
	}); err != nil {
		return nil, 0, fmt.Errorf("packer: V2N PIC: %w", err)
	}
	immPos := 10

	// === Section 2: CPUID prologue (verbatim from V2) ===
	check := func(err error, where string) error {
		if err != nil {
			return fmt.Errorf("packer: V2N %s: %w", where, err)
		}
		return nil
	}
	if e := check(b.SUB(amd64.RSP, amd64.Imm(16)), "sub rsp"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOV(amd64.RDI, amd64.RSP), "mov rdi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.XOR(amd64.RAX, amd64.RAX), "xor eax"); e != nil {
		return nil, 0, e
	}
	if e := check(b.RawBytes([]byte{0x0f, 0xa2}), "cpuid"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.MemOp{Base: amd64.RDI}, amd64.RBX), "mov [rdi] ebx"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 4}, amd64.RDX), "mov [rdi+4] edx"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 8}, amd64.RCX), "mov [rdi+8] ecx"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOV(amd64.RSI, amd64.RDI), "mov rsi rdi"); e != nil {
		return nil, 0, e
	}

	// === Section 2.5: CPUID EAX=1 → save ECX features to [rdi+12] ===
	// Used by the PT_CPUID_FEATURES predicate. The 16-byte stack
	// scratch was pre-allocated for the 12-byte vendor; the
	// remaining 4 bytes fit the feature ECX. Layout:
	//   [rsi+0..11]   12-byte CPUID vendor (canonical)
	//   [rsi+12..15]  4-byte CPUID[1].ECX (feature flags 1)
	//
	// mov eax, 1   (b8 01 00 00 00 — 5 bytes)
	// cpuid        (0f a2 — 2 bytes)
	// mov [rdi+12], ecx (89 4f 0c — 3 bytes)
	if e := check(b.RawBytes([]byte{0xb8, 0x01, 0x00, 0x00, 0x00}), "mov eax 1"); e != nil {
		return nil, 0, e
	}
	if e := check(b.RawBytes([]byte{0x0f, 0xa2}), "cpuid #1"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 12}, amd64.RCX), "mov [rdi+12] ecx"); e != nil {
		return nil, 0, e
	}

	// === Section 3: Loop setup ===
	if e := check(b.MOVZWL(amd64.RCX, amd64.MemOp{Base: amd64.R15, Disp: 6}), "movzx ecx"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.R8, amd64.MemOp{Base: amd64.R15, Disp: 8}), "mov r8d"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.R8, amd64.R15), "add r8 r15"); e != nil {
		return nil, 0, e
	}
	if e := check(b.XOR(amd64.RAX, amd64.RAX), "xor eax 2"); e != nil {
		return nil, 0, e
	}

	// === Section 4: Loop body with AL-accumulator + negate ===
	loopLabel := b.Label("loop")
	matchedLabel := amd64.LabelRef("matched")
	noMatchLabel := amd64.LabelRef("no_match")
	// .next label exists (declared via b.Label("next") below) but no
	// explicit Jcc targets it — the entry_done block falls through to
	// .next when AL=0. Label is used by the trailing `jmp .loop`.
	skipVendorLabel := amd64.LabelRef("skip_vendor")
	vendorLowMismatch := amd64.LabelRef("vendor_low_mismatch")
	vendorFail := amd64.LabelRef("vendor_fail")
	entryDoneLabel := amd64.LabelRef("entry_done")

	// cmp eax, ecx; jge .no_match
	if e := check(b.CMP(amd64.RAX, amd64.RCX), "cmp eax ecx"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JGE(noMatchLabel), "jge no_match"); e != nil {
		return nil, 0, e
	}

	// mov r12b, 1               — assume match (use R12 as the AL-
	// accumulator instead of AL itself; AL is the low byte of EAX
	// which is the loop counter — clobbering it broke the
	// dispatch on PT_MATCH_ALL bundles where the counter must
	// remain 0).
	// Encoding: 41 b4 01 = mov r12b, 1
	if e := check(b.RawBytes([]byte{0x41, 0xb4, 0x01}), "mov r12b 1"); e != nil {
		return nil, 0, e
	}

	// movzx r9d, byte [r8]      — predType
	if e := check(b.MOVZX(amd64.R9, amd64.MemOp{Base: amd64.R8}), "movzx r9d"); e != nil {
		return nil, 0, e
	}

	// test r9b, 8                — PT_MATCH_ALL — RawBytes (Plan 9 quirk)
	if e := check(b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x08}), "test r9b 8"); e != nil {
		return nil, 0, e
	}
	// jnz .entry_done            — fast-path: AL already 1
	if e := check(b.JNZ(entryDoneLabel), "jnz entry_done"); e != nil {
		return nil, 0, e
	}

	// test r9b, 1                — PT_CPUID_VENDOR — RawBytes
	if e := check(b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x01}), "test r9b 1"); e != nil {
		return nil, 0, e
	}
	// jz .skip_vendor            — bit not set, leave AL=1 (no constraint here)
	if e := check(b.JE(skipVendorLabel), "jz skip_vendor"); e != nil {
		return nil, 0, e
	}

	// Vendor compare
	if e := check(b.MOV(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 4}), "mov r10 [r8+4]"); e != nil {
		return nil, 0, e
	}
	if e := check(b.CMP(amd64.R10, amd64.MemOp{Base: amd64.RSI}), "cmp r10 [rsi]"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JNZ(vendorLowMismatch), "jne vendor_low_mismatch"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 12}), "mov r10d [r8+12]"); e != nil {
		return nil, 0, e
	}
	if e := check(b.CMPL(amd64.R10, amd64.MemOp{Base: amd64.RSI, Disp: 8}), "cmpl r10d [rsi+8]"); e != nil {
		return nil, 0, e
	}
	// je .skip_vendor            — full match, AL=1
	if e := check(b.JE(skipVendorLabel), "je skip_vendor (match)"); e != nil {
		return nil, 0, e
	}

	// .vendor_low_mismatch:
	b.Label("vendor_low_mismatch")
	// Wildcard check (entry vendor all zero)
	if e := check(b.MOV(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 4}), "vlm mov r10"); e != nil {
		return nil, 0, e
	}
	if e := check(b.TEST(amd64.R10, amd64.R10), "vlm test r10"); e != nil {
		return nil, 0, e
	}
	// jnz .vendor_fail
	if e := check(b.JNZ(vendorFail), "jnz vendor_fail"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 12}), "vlm mov r10d"); e != nil {
		return nil, 0, e
	}
	if e := check(b.TEST(amd64.R10, amd64.R10), "vlm test r10d"); e != nil {
		return nil, 0, e
	}
	// jz .skip_vendor — wildcard match, AL=1
	if e := check(b.JE(skipVendorLabel), "jz skip_vendor (wildcard)"); e != nil {
		return nil, 0, e
	}

	// .vendor_fail: R12B = 0 (mark as no-match in the accumulator).
	// Encoding: 45 30 e4 = xor r12b, r12b (3 bytes; clobbers
	// only R12, NOT EAX/RAX which is the loop counter).
	b.Label("vendor_fail")
	if e := check(b.RawBytes([]byte{0x45, 0x30, 0xe4}), "xor r12b r12b"); e != nil {
		return nil, 0, e
	}
	// fallthrough to .skip_vendor

	// .skip_vendor — PT_CPUID_FEATURES check (Tier 🔴 #1.3)
	b.Label("skip_vendor")
	skipFeaturesLabel := amd64.LabelRef("skip_features")
	// test r9b, 4  — PT_CPUID_FEATURES bit
	if e := check(b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x04}), "test r9b 4"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JE(skipFeaturesLabel), "jz skip_features"); e != nil {
		return nil, 0, e
	}
	// mov r10d, [rsi+12]  — host CPUID[1].ECX features
	if e := check(b.MOVL(amd64.R10, amd64.MemOp{Base: amd64.RSI, Disp: 12}), "mov r10d features"); e != nil {
		return nil, 0, e
	}
	// and r10d, [r8+24]  — mask with CPUIDFeatureMask
	// Encoding: 44 23 50 18 (REX.R=1, opcode 23 AND r32, r/m32,
	// ModRM=mod=01 reg=010=R10 rm=000=RAX-base disp8=0x18... wait
	// rm needs to be R8. Let me redo:
	// AND r10d, [r8+24]:
	//   REX: W=0, R=1 (R10 extension), X=0, B=1 (R8 base extension) → 0x45
	//   Opcode: 23 (AND r32, r/m32)
	//   ModRM: mod=01 reg=010 rm=000 → 01_010_000 = 0x50
	//   Disp8: 0x18
	if e := check(b.RawBytes([]byte{0x45, 0x23, 0x50, 0x18}), "and r10d [r8+24]"); e != nil {
		return nil, 0, e
	}
	// cmp r10d, [r8+28]  — vs CPUIDFeatureValue
	// Encoding via Builder.CMPL with the operand-swap convention.
	if e := check(b.CMPL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 28}), "cmpl r10d [r8+28]"); e != nil {
		return nil, 0, e
	}
	// je .skip_features  — masked features match value → keep R12B
	if e := check(b.JE(skipFeaturesLabel), "je skip_features (match)"); e != nil {
		return nil, 0, e
	}
	// fallthrough → no match → clear R12B
	if e := check(b.RawBytes([]byte{0x45, 0x30, 0xe4}), "xor r12b r12b (features fail)"); e != nil {
		return nil, 0, e
	}

	b.Label("skip_features")
	// fallthrough to .entry_done

	// .entry_done: apply negate flag
	b.Label("entry_done")
	// movzx r9d, byte [r8+1]    — negate byte
	if e := check(b.MOVZX(amd64.R9, amd64.MemOp{Base: amd64.R8, Disp: 1}), "movzx negate"); e != nil {
		return nil, 0, e
	}
	// and r9b, 1                 — RawBytes (Plan 9 quirk on 8-bit imm AND)
	if e := check(b.RawBytes([]byte{0x41, 0x80, 0xe1, 0x01}), "and r9b 1"); e != nil {
		return nil, 0, e
	}
	// xor r12b, r9b              — flip if negate set
	// Encoding: 45 30 cc (REX.RB, opcode 30, ModRM=11_001_100 →
	// reg=R9, rm=R12).
	if e := check(b.RawBytes([]byte{0x45, 0x30, 0xcc}), "xor r12b r9b"); e != nil {
		return nil, 0, e
	}
	// test r12b, r12b
	// Encoding: 45 84 e4
	if e := check(b.RawBytes([]byte{0x45, 0x84, 0xe4}), "test r12b r12b"); e != nil {
		return nil, 0, e
	}
	// jnz .matched
	if e := check(b.JNZ(matchedLabel), "jnz matched final"); e != nil {
		return nil, 0, e
	}
	// fallthrough to .next

	// .next
	b.Label("next")
	if e := check(b.ADD(amd64.R8, amd64.Imm(48)), "next add r8"); e != nil {
		return nil, 0, e
	}
	if e := check(b.INC(amd64.RAX), "next inc"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JMP(loopLabel), "next jmp loop"); e != nil {
		return nil, 0, e
	}

	// === Section 5: .no_match Linux sys_exit_group(0) ===
	b.Label("no_match")
	if e := check(b.MOVL(amd64.RAX, amd64.Imm(231)), "no_match mov eax"); e != nil {
		return nil, 0, e
	}
	if e := check(b.XOR(amd64.RDI, amd64.RDI), "no_match xor edi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.SYSCALL(), "no_match syscall"); e != nil {
		return nil, 0, e
	}

	// === Section 6: .matched + decrypt + JMP (verbatim from V2) ===
	b.Label("matched")
	if e := check(b.MOVL(amd64.R9, amd64.MemOp{Base: amd64.R15, Disp: 12}), "matched mov r9d"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.R10, amd64.RAX), "matched mov r10d"); e != nil {
		return nil, 0, e
	}
	if e := check(b.SHL(amd64.R10, amd64.Imm(5)), "matched shl"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.R9, amd64.R10), "matched add"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.R9, amd64.R15), "matched add r15"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOV(amd64.RCX, amd64.R9), "matched mov rcx"); e != nil {
		return nil, 0, e
	}

	if e := check(b.MOVL(amd64.RDI, amd64.MemOp{Base: amd64.RCX}), "dec mov edi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.RDI, amd64.R15), "dec add rdi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.RSI, amd64.MemOp{Base: amd64.RCX, Disp: 4}), "dec mov esi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.LEA(amd64.R8, amd64.MemOp{Base: amd64.RCX, Disp: 16}), "dec lea r8"); e != nil {
		return nil, 0, e
	}
	if e := check(b.XOR(amd64.R9, amd64.R9), "dec xor r9"); e != nil {
		return nil, 0, e
	}

	decLabel := b.Label("dec")
	jmpPayloadLabel := amd64.LabelRef("jmp_payload")
	if e := check(b.TEST(amd64.RSI, amd64.RSI), "dec test esi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JE(jmpPayloadLabel), "dec jz jmp_payload"); e != nil {
		return nil, 0, e
	}
	// Decrypt 6-step (Builder-emitted; was RawBytes before #2.1):
	//   mov al, [rdi]               ; load ciphertext byte
	//   mov dl, r9b                 ; copy round index
	//   and dl, 15                  ; SBox is 16 entries
	//   movzx edx, dl               ; widen for SIB indexing
	//   xor al, [r8+rdx]            ; SBox lookup XOR
	//   mov [rdi], al               ; store plaintext byte
	if e := check(b.MOVBReg(amd64.RAX, amd64.MemOp{Base: amd64.RDI}), "dec mov al [rdi]"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVBReg(amd64.RDX, amd64.R9), "dec mov dl r9b"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ANDB(amd64.RDX, amd64.Imm(0x0f)), "dec and dl 15"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVZBL(amd64.RDX, amd64.RDX), "dec movzx edx dl"); e != nil {
		return nil, 0, e
	}
	if e := check(b.XORB(amd64.RAX, amd64.MemOp{Base: amd64.R8, Index: amd64.RDX, Scale: 1}), "dec xor al [r8+rdx]"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVB(amd64.MemOp{Base: amd64.RDI}, amd64.RAX), "dec mov [rdi] al"); e != nil {
		return nil, 0, e
	}
	if e := check(b.INC(amd64.RDI), "dec inc rdi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.INC(amd64.R9), "dec inc r9"); e != nil {
		return nil, 0, e
	}
	if e := check(b.DEC(amd64.RSI), "dec dec esi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JMP(decLabel), "dec jmp dec"); e != nil {
		return nil, 0, e
	}

	b.Label("jmp_payload")
	if e := check(b.MOVL(amd64.RDI, amd64.MemOp{Base: amd64.RCX}), "jp mov edi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.RDI, amd64.R15), "jp add rdi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JMPReg(amd64.RDI), "jp jmp rdi"); e != nil {
		return nil, 0, e
	}

	out, err := b.Encode()
	if err != nil {
		return nil, 0, fmt.Errorf("packer: V2N encode: %w", err)
	}
	return out, immPos, nil
}
