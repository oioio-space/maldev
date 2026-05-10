package packer

import (
	"testing"
)

// TestBundleStubV2NWBuilds asserts the V2-Negate-Windows-Build stub
// assembles cleanly + produces a non-empty byte stream. Sanity check
// before any runtime test.
func TestBundleStubV2NWBuilds(t *testing.T) {
	stub, immPos, err := bundleStubV2NegateWinBuildWindows()
	if err != nil {
		t.Fatalf("bundleStubV2NegateWinBuildWindows: %v", err)
	}
	t.Logf("V2NW stub: len=%d immPos=%d", len(stub), immPos)
	if immPos != bundleOffsetImm32Pos {
		t.Errorf("immPos = %d, want %d", immPos, bundleOffsetImm32Pos)
	}
	// V2 = 204, V2-Negate ≈ 226, V2NW pre-#2.2 ≈ 458; Phase 3c
	// adds ~280 B for the AES-CTR path (CipherType dispatch ~12 B +
	// emitAESCTRDecryptLoop 243 B + AES-CTR epilogue ~25 B), bringing
	// V2NW to ~740 B. Bound includes headroom for slot polymorphism
	// + future feature additions.
	if len(stub) < 600 || len(stub) > 900 {
		t.Errorf("V2NW stub length %d outside expected [600..900]", len(stub))
	}
}

// TestBundleStubV2NW_PICTrampolinePrefix asserts the first 14 B
// match the canonical PIC trampoline byte-for-byte (so
// bundleOffsetImm32Pos still points at a valid imm32 location).
func TestBundleStubV2NW_PICTrampolinePrefix(t *testing.T) {
	stub, _, err := bundleStubV2NegateWinBuildWindows()
	if err != nil {
		t.Fatalf("bundleStubV2NegateWinBuildWindows: %v", err)
	}
	if len(stub) < 14 {
		t.Fatalf("stub too short: %d", len(stub))
	}
	want := []byte{
		0xe8, 0x00, 0x00, 0x00, 0x00, // call .pic
		0x41, 0x5f, // pop r15
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00, // add r15, imm32
	}
	for i, w := range want {
		if stub[i] != w {
			t.Errorf("PIC byte %d: got %#02x, want %#02x", i, stub[i], w)
		}
	}
}
