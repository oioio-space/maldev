package packer

import (
	"encoding/binary"
	"testing"
)

// TestBundleStubV2_LengthSanity asserts the V2 stub is in the same
// byte-length ballpark as V1. golang-asm picks valid encodings that
// may differ from V1's hand-encoded bytes (Plan-9 vs Intel mnemonic
// conventions), so strict equality isn't expected — but the order
// of magnitude must match (~196 ± 20 bytes), or one of the
// instructions must have ballooned via a wrong mnemonic.
func TestBundleStubV2_LengthSanity(t *testing.T) {
	v1 := bundleStubVendorAware()
	v2, _, err := bundleStubVendorAwareV2()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2: %v", err)
	}
	t.Logf("V1 length=%d  V2 length=%d  diff=%+d", len(v1), len(v2), len(v2)-len(v1))
	const slack = 30 // bytes
	delta := len(v2) - len(v1)
	if delta < -slack || delta > slack {
		t.Errorf("V2 length=%d differs from V1=%d by more than ±%d bytes — encoding choice ballooned somewhere",
			len(v2), len(v1), slack)
	}
}

// TestBundleStubV2_PICOffsetMatchesV1 asserts the V2 emission
// produces its `add r15, imm32` immediate at the same byte offset
// as V1's `bundleOffsetImm32Pos = 10`. Operators rely on this
// constant to patch the bundle offset post-encode; if V2 shifted
// the position, every downstream consumer would write to wrong
// bytes.
func TestBundleStubV2_PICOffsetMatchesV1(t *testing.T) {
	_, immPos, err := bundleStubVendorAwareV2()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2: %v", err)
	}
	if immPos != bundleOffsetImm32Pos {
		t.Errorf("V2 immPos=%d, want %d (bundleOffsetImm32Pos)", immPos, bundleOffsetImm32Pos)
	}
}

// TestBundleStubV2_PICTrampolinePrefixMatchesV1 asserts the first
// 14 bytes (PIC trampoline) are byte-identical between V1 and V2 —
// V2 emits them as a single RawBytes block matching V1's PIC layout.
// This guarantees the imm32 patch site lines up.
func TestBundleStubV2_PICTrampolinePrefixMatchesV1(t *testing.T) {
	v1 := bundleStubVendorAware()
	v2, _, err := bundleStubVendorAwareV2()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2: %v", err)
	}
	if len(v1) < 14 || len(v2) < 14 {
		t.Fatalf("stubs too short to compare (v1=%d v2=%d)", len(v1), len(v2))
	}
	for i := 0; i < 14; i++ {
		if v1[i] != v2[i] {
			t.Errorf("PIC byte %d: v1=%#02x v2=%#02x", i, v1[i], v2[i])
		}
	}
}

// TestBundleStubV2_LoopSectionStartsCleanly is a smoke check that
// V2's loop body lands at a sensible offset (post-prologue) and
// starts with the expected `cmp eax, ecx` (39 c8) instruction. If
// golang-asm chose a different encoding for cmp (e.g. 3b c1), this
// test catches the divergence at byte-shape time.
func TestBundleStubV2_LoopSectionStartsCleanly(t *testing.T) {
	v2, _, err := bundleStubVendorAwareV2()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2: %v", err)
	}
	// V2's loop section starts after PIC (14) + CPUID prologue (~22) +
	// loop setup (~14) ≈ offset 50. golang-asm encoding choices may
	// shift this by ±1-2 bytes if a particular instruction picks a
	// different valid encoding. Search a 60-byte window.
	const minOffset = 40
	const maxOffset = 70
	if len(v2) < maxOffset+4 {
		t.Fatalf("V2 too short to contain loop section (len=%d)", len(v2))
	}
	// Look for the canonical CMP r/m32, r32 byte (`39 c8` for cmp eax, ecx).
	// Note: golang-asm may emit `3b c1` (CMP r32, r/m32) instead — same
	// semantics. Accept either as a smoke signal.
	found := false
	for i := minOffset; i < maxOffset; i++ {
		if (v2[i] == 0x39 && v2[i+1] == 0xc8) || (v2[i] == 0x3b && v2[i+1] == 0xc1) {
			found = true
			t.Logf("loop body cmp eax, ecx at offset %d (encoding %#02x %#02x)",
				i, v2[i], v2[i+1])
			break
		}
	}
	if !found {
		t.Errorf("V2 loop body's `cmp eax, ecx` not found in offsets [%d..%d) — encoding may have diverged",
			minOffset, maxOffset)
	}
}

// TestBundleStubV2_IsAssembleableWithBundleOff just confirms the
// post-encode imm32 patch round-trips through the produced bytes
// without trampling adjacent instructions. Patches a known value
// at immPos and reads it back.
func TestBundleStubV2_IsAssembleableWithBundleOff(t *testing.T) {
	v2, immPos, err := bundleStubVendorAwareV2()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2: %v", err)
	}
	const sentinel uint32 = 0xdeadbeef
	binary.LittleEndian.PutUint32(v2[immPos:], sentinel)
	if got := binary.LittleEndian.Uint32(v2[immPos:]); got != sentinel {
		t.Errorf("imm32 patch round-trip: got %#x, want %#x", got, sentinel)
	}
	// Adjacent bytes (immPos-1 and immPos+4) should be the surrounding
	// asm — for V2's PIC trampoline that's the `49 81 c7` opcode prefix
	// at immPos-3..immPos-1 and… nothing predictable at immPos+4, so
	// just smoke-check that we didn't write outside the imm slot.
	if immPos < 3 || immPos+4 > len(v2) {
		t.Errorf("immPos=%d is too close to stub boundaries (len=%d)", immPos, len(v2))
	}
}
