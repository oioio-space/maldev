package packer

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// TestEmitBundlePICTrampoline pins the 14-byte CALL+POP+ADD PIC
// prologue and asserts the returned imm32 patch position is the
// canonical 10 (= length of `call .pic` + `pop r15` = 5 + 2 +
// REX prefix + opcode + ModRM of `add r15, imm32` = 3 → 10).
// Future Builder changes that shift this byte sequence would
// silently corrupt every wrapped bundle (the wrap layer writes
// 4 bytes at bundleStubPICImmPos to thread the bundle-base
// distance into the running stub).
func TestEmitBundlePICTrampoline(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	immPos, err := emitBundlePICTrampoline(b)
	if err != nil {
		t.Fatalf("emitBundlePICTrampoline: %v", err)
	}
	if immPos != bundleStubPICImmPos {
		t.Errorf("immPos = %d, want %d (bundleStubPICImmPos)", immPos, bundleStubPICImmPos)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		0xe8, 0x00, 0x00, 0x00, 0x00, // call .pic
		0x41, 0x5f, // pop r15
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00, // add r15, imm32
	}
	if !bytes.Equal(out, want) {
		t.Errorf("PIC trampoline:\n got % x\nwant % x", out, want)
	}
}

// TestEmitCPUIDVendorPrologue pins the 23-byte CPUID-leaf-0 vendor
// read + RSI pinning sequence. Encoded length must stay stable
// because slot A's junk insertion at offset 14 (past the PIC) assumes
// the next 23 bytes are the prologue — a length change would shift
// every subsequent label and break all Jcc displacements.
func TestEmitCPUIDVendorPrologue(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := emitCPUIDVendorPrologue(b); err != nil {
		t.Fatalf("emitCPUIDVendorPrologue: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		0x48, 0x83, 0xec, 0x10, // sub rsp, 16
		0x48, 0x89, 0xe7, // mov rdi, rsp
		0x48, 0x31, 0xc0, // xor eax, eax
		0x0f, 0xa2, // cpuid
		0x89, 0x1f, // mov [rdi], ebx
		0x89, 0x57, 0x04, // mov [rdi+4], edx
		0x89, 0x4f, 0x08, // mov [rdi+8], ecx
		0x48, 0x89, 0xfe, // mov rsi, rdi
	}
	if !bytes.Equal(out, want) {
		t.Errorf("CPUID vendor prologue (%d B):\n got % x\nwant % x", len(out), out, want)
	}
}

// TestEmitCPUIDFeaturesProbe pins the 10-byte CPUID-leaf-1 +
// features-store sequence used by PT_CPUID_FEATURES predicates.
// The store goes to [rdi+12] — the 4-byte unused tail of the
// 16-byte stack scratch [emitCPUIDVendorPrologue] allocates; if
// that displacement changes, PT_CPUID_FEATURES would silently read
// uninitialised memory.
func TestEmitCPUIDFeaturesProbe(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := emitCPUIDFeaturesProbe(b); err != nil {
		t.Fatalf("emitCPUIDFeaturesProbe: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0x0f, 0xa2, // cpuid
		0x89, 0x4f, 0x0c, // mov [rdi+12], ecx
	}
	if !bytes.Equal(out, want) {
		t.Errorf("CPUID features probe (%d B):\n got % x\nwant % x", len(out), out, want)
	}
}

// TestEmitAESCTRBlockDecrypt pins the 148-byte AES-128-CTR block
// decryption sequence. Per-instruction shape:
//
//   - 2 × PXOR (counter copy via clear+xor)             =  8 B
//   - 11 × MOVDQU XMM2, [R8+disp]  (round keys)
//     · 1 disp=0 (3 B disp encoding):                4 B
//     · 7 disp ∈ [16..112] (disp8, +1 B):           10 B each = 70 B
//     · 3 disp ∈ [128..160] (disp32, +4 B):         13 B each = 39 B
//   - 1 × PXOR (whitening) + 9 × AESENC + 1 × AESENCLAST
//   - 1 × MOVDQU XMM2, [RSI]   (load ciphertext)
//   - 1 × PXOR (apply keystream)
//   - 1 × MOVDQU [RDI], XMM2   (store plaintext)
//
// Total = 148 B. Encoding pinned exactly so future Builder primitive
// changes (e.g. AESENC byte shift) surface as test failure before
// hitting any stub. AES-NI is required at runtime — the host CPU
// must advertise the AES bit in CPUID[1].ECX (every desktop x86-64
// since ~2010 does).
func TestEmitAESCTRBlockDecrypt(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := emitAESCTRBlockDecrypt(b); err != nil {
		t.Fatalf("emitAESCTRBlockDecrypt: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		// pxor xmm1, xmm1 ; pxor xmm1, xmm0
		0x66, 0x0f, 0xef, 0xc9,
		0x66, 0x0f, 0xef, 0xc8,
		// movdqu xmm2, [r8+0] ; pxor xmm1, xmm2  (round 0 whitening)
		0xf3, 0x41, 0x0f, 0x6f, 0x10,
		0x66, 0x0f, 0xef, 0xca,
		// Round 1: movdqu xmm2, [r8+16] ; aesenc xmm1, xmm2
		0xf3, 0x41, 0x0f, 0x6f, 0x50, 0x10,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 2: [r8+32]
		0xf3, 0x41, 0x0f, 0x6f, 0x50, 0x20,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 3: [r8+48]
		0xf3, 0x41, 0x0f, 0x6f, 0x50, 0x30,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 4: [r8+64]
		0xf3, 0x41, 0x0f, 0x6f, 0x50, 0x40,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 5: [r8+80]
		0xf3, 0x41, 0x0f, 0x6f, 0x50, 0x50,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 6: [r8+96]
		0xf3, 0x41, 0x0f, 0x6f, 0x50, 0x60,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 7: [r8+112]
		0xf3, 0x41, 0x0f, 0x6f, 0x50, 0x70,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 8: [r8+128] (disp32 because >0x7f)
		0xf3, 0x41, 0x0f, 0x6f, 0x90, 0x80, 0x00, 0x00, 0x00,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 9: [r8+144]
		0xf3, 0x41, 0x0f, 0x6f, 0x90, 0x90, 0x00, 0x00, 0x00,
		0x66, 0x0f, 0x38, 0xdc, 0xca,
		// Round 10: [r8+160] ; aesenclast xmm1, xmm2
		0xf3, 0x41, 0x0f, 0x6f, 0x90, 0xa0, 0x00, 0x00, 0x00,
		0x66, 0x0f, 0x38, 0xdd, 0xca,
		// Apply keystream: movdqu xmm2, [rsi] ; pxor xmm2, xmm1 ; movdqu [rdi], xmm2
		0xf3, 0x0f, 0x6f, 0x16,
		0x66, 0x0f, 0xef, 0xd1,
		0xf3, 0x0f, 0x7f, 0x17,
	}
	if !bytes.Equal(out, want) {
		t.Errorf("AES-CTR block-decrypt (%d B):\n got % x\nwant % x", len(out), out, want)
	}
	if len(out) != 148 {
		t.Errorf("length = %d, want 148 (regression sentinel for stub size budget)", len(out))
	}
}

// TestEmitAESCTRDecryptLoop pins the Phase 3c stub-side AES-CTR
// decrypt loop's structure: setup prefix, single-block body via
// emitAESCTRBlockDecrypt, BE-counter increment via BSWAP, and the
// loop epilogue. Total length is the regression sentinel — a wrong
// Builder primitive change or a missing label resolve surfaces here
// before reaching V2NW integration.
func TestEmitAESCTRDecryptLoop(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := emitAESCTRDecryptLoop(b); err != nil {
		t.Fatalf("emitAESCTRDecryptLoop: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Length sentinel (243 B as of v0.92.0 Phase 3c-prep). Setup
	// = 32 B; loop body = test r9 (3) + jz (2) + block-decrypt (148)
	// + counter-inc (40) + advance (9) + jmp (5) + 4 B padding/labels.
	if len(out) < 230 || len(out) > 260 {
		t.Errorf("loop length = %d B, want ~243 (regression — Phase 3c stub-size budget shifted)", len(out))
	}

	// Setup prefix pin — first 8 instructions before the .aes_loop
	// label. Stable byte sequence (no Jcc displacements yet):
	wantPrefix := []byte{
		0xf3, 0x0f, 0x6f, 0x07, // movdqu xmm0, [rdi]   (load IV)
		0x48, 0x83, 0xc7, 0x10, // add rdi, 16          (skip past IV)
		0x8b, 0x51, 0x04, // mov edx, [rcx+4]    (DataSize)
		0x48, 0x81, 0xea, 0xc0, 0x00, 0x00, 0x00, // sub rdx, 192        (-16 IV -176 RK)
		0x49, 0x89, 0xf8, // mov r8, rdi
		0x49, 0x01, 0xd0, // add r8, rdx         (R8 = round keys)
		0x48, 0x89, 0xfe, // mov rsi, rdi        (in-place source)
		0x49, 0x89, 0xd1, // mov r9, rdx         (R9 = remaining)
	}
	if !bytes.Equal(out[:len(wantPrefix)], wantPrefix) {
		t.Errorf("setup prefix:\n got % x\nwant % x", out[:len(wantPrefix)], wantPrefix)
	}
}

// TestEmitBundleLoopSetup pins the 15-byte scan-loop initialiser:
// reads entry count from BundleHeader (offset 6), entries RVA
// (offset 8) + folds R15 to make it absolute, zeros loop counter.
// Displacements (6, 8) are the wire-format offsets of
// BundleHeader.Count and BundleHeader.EntriesRVA — changing the
// wire format without updating these bytes would silently dispatch
// against garbage.
func TestEmitBundleLoopSetup(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := emitBundleLoopSetup(b); err != nil {
		t.Fatalf("emitBundleLoopSetup: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	want := []byte{
		0x41, 0x0f, 0xb7, 0x4f, 0x06, // movzx ecx, word [r15+6]
		0x45, 0x8b, 0x47, 0x08, // mov r8d, [r15+8]
		0x4d, 0x01, 0xf8, // add r8, r15
		0x48, 0x31, 0xc0, // xor eax, eax
	}
	if !bytes.Equal(out, want) {
		t.Errorf("loop setup (%d B):\n got % x\nwant % x", len(out), out, want)
	}
}
