package transform_test

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// minPEWithImageVersion extends minPEWithOptHdr to ensure the
// Optional Header reaches at least past the ImageVersion fields
// (offset 0x2E + 2 = 0x30 from optOff). 0x100 total bytes are
// plenty.
func minPEWithImageVersion(t *testing.T) []byte {
	t.Helper()
	const peOff = 0x40
	out := make([]byte, 0x100)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:transform.PEELfanewOffset+4], peOff)
	binary.LittleEndian.PutUint32(out[peOff:peOff+4], 0x00004550) // "PE\0\0"
	return out
}

func TestPatchPEImageVersion_WritesAtCorrectOffsets(t *testing.T) {
	pe := minPEWithImageVersion(t)
	if err := transform.PatchPEImageVersion(pe, 0xABCD, 0x1234); err != nil {
		t.Fatalf("PatchPEImageVersion: %v", err)
	}
	const peOff = 0x40
	optOff := peOff + 4 + 20
	majOff := optOff + transform.OptMajorImageVersionOffset
	minOff := optOff + transform.OptMinorImageVersionOffset
	if got := binary.LittleEndian.Uint16(pe[majOff:]); got != 0xABCD {
		t.Errorf("MajorImageVersion = 0x%X, want 0xABCD", got)
	}
	if got := binary.LittleEndian.Uint16(pe[minOff:]); got != 0x1234 {
		t.Errorf("MinorImageVersion = 0x%X, want 0x1234", got)
	}
}

func TestPatchPEImageVersion_RejectsTruncated(t *testing.T) {
	if err := transform.PatchPEImageVersion([]byte{0x4D, 0x5A}, 1, 0); err == nil {
		t.Error("PatchPEImageVersion on 2-byte input: want error, got nil")
	}
}

func TestPatchPEImageVersion_RejectsELfanewOverflow(t *testing.T) {
	pe := make([]byte, 0x80)
	pe[0] = 'M'
	pe[1] = 'Z'
	binary.LittleEndian.PutUint32(pe[transform.PEELfanewOffset:transform.PEELfanewOffset+4], 0x1000)
	if err := transform.PatchPEImageVersion(pe, 1, 0); err == nil {
		t.Error("PatchPEImageVersion with bogus e_lfanew: want error, got nil")
	}
}

func TestRandomImageVersion_WithinPlausibleRange(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		major, minor := transform.RandomImageVersion(rng)
		if major > 9 {
			t.Errorf("major=%d outside [0, 9]", major)
		}
		if minor > 99 {
			t.Errorf("minor=%d outside [0, 99]", minor)
		}
	}
}

func TestRandomImageVersion_DeterministicGivenSeed(t *testing.T) {
	a1, a2 := transform.RandomImageVersion(rand.New(rand.NewSource(777)))
	b1, b2 := transform.RandomImageVersion(rand.New(rand.NewSource(777)))
	if a1 != b1 || a2 != b2 {
		t.Errorf("same seed produced %d.%d vs %d.%d", a1, a2, b1, b2)
	}
}

func TestRandomImageVersion_DiffersAcrossSeeds(t *testing.T) {
	a1, a2 := transform.RandomImageVersion(rand.New(rand.NewSource(1)))
	b1, b2 := transform.RandomImageVersion(rand.New(rand.NewSource(2)))
	if a1 == b1 && a2 == b2 {
		t.Errorf("seeds 1 and 2 collided on %d.%d", a1, a2)
	}
}
