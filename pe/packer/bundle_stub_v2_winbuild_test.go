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
	// V2 = 204, V2-Negate ≈ 226, V2NW expected ≈ 280-310 (adds
	// EmitPEBBuildRead 15 B + R13 save 3 B + PT_WIN_BUILD block ~30 B
	// + §2 ExitProcess inline 143 B). Sanity bound.
	if len(stub) < 350 || len(stub) > 500 {
		t.Errorf("V2NW stub length %d outside expected [350..500]", len(stub))
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
