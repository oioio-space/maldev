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
