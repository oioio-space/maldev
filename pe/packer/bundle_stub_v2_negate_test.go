package packer

import (
	"bytes"
	"testing"
)

// TestBundleStubV2N_PICOffsetMatchesConst pins the PIC trampoline's
// imm32 patch site at [bundleOffsetImm32Pos]. Operators / wrap APIs
// rely on this constant to write the bundle-base distance into the
// `add r15, imm32` instruction post-encode; a Builder choice that
// shifted the offset would corrupt every wrapped binary silently.
// V2-Negate inherited the 14-byte PIC layout from V2; this test
// guards future Builder primitive changes from breaking it.
func TestBundleStubV2N_PICOffsetMatchesConst(t *testing.T) {
	stub, immPos, err := bundleStubVendorAwareV2Negate()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2Negate: %v", err)
	}
	if immPos != bundleOffsetImm32Pos {
		t.Errorf("V2-Negate immPos=%d, want %d (bundleOffsetImm32Pos)", immPos, bundleOffsetImm32Pos)
	}
	if len(stub) < bundleOffsetImm32Pos+4 {
		t.Fatalf("stub too short (%d B) to contain imm32 site", len(stub))
	}
}

// TestBundleStubV2N_PICTrampolinePrefix pins the first 14 bytes of
// V2-Negate as the canonical PIC trampoline shape:
//   call .pic                   ; e8 00 00 00 00
//   pop  r15                    ; 41 5f
//   add  r15, imm32 (placeholder); 49 81 c7 00 00 00 00
// Builder migration tests previously asserted this against the V1
// hand-encoded blob; with V1 retired (#3.3), the canonical shape is
// pinned directly here.
func TestBundleStubV2N_PICTrampolinePrefix(t *testing.T) {
	stub, _, err := bundleStubVendorAwareV2Negate()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2Negate: %v", err)
	}
	want := []byte{
		0xe8, 0x00, 0x00, 0x00, 0x00, // call .pic
		0x41, 0x5f, // pop r15
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00, // add r15, imm32 (zero)
	}
	if len(stub) < len(want) {
		t.Fatalf("stub too short (%d < %d)", len(stub), len(want))
	}
	if !bytes.Equal(stub[:len(want)], want) {
		t.Errorf("PIC prefix:\n got % x\nwant % x", stub[:len(want)], want)
	}
}
