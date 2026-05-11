package transform_test

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// minPEWithOptHdr extends minPE with enough room past the COFF
// header to hold a 4-byte Optional Header head (the linker version
// fields live in the first 4 bytes).
func minPEWithOptHdr(t *testing.T) []byte {
	t.Helper()
	const peOff = 0x40
	out := make([]byte, 0x100)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:transform.PEELfanewOffset+4], peOff)
	binary.LittleEndian.PutUint32(out[peOff:peOff+4], 0x00004550) // "PE\0\0"
	return out
}

func TestPatchPELinkerVersion_WritesAtCorrectOffsets(t *testing.T) {
	pe := minPEWithOptHdr(t)
	if err := transform.PatchPELinkerVersion(pe, 14, 32); err != nil {
		t.Fatalf("PatchPELinkerVersion: %v", err)
	}
	const peOff = 0x40
	optOff := peOff + 4 + 20
	if got := pe[optOff+transform.OptMajorLinkerVersionOffset]; got != 14 {
		t.Errorf("MajorLinkerVersion = %d, want 14", got)
	}
	if got := pe[optOff+transform.OptMinorLinkerVersionOffset]; got != 32 {
		t.Errorf("MinorLinkerVersion = %d, want 32", got)
	}
}

func TestPatchPELinkerVersion_RejectsTruncated(t *testing.T) {
	if err := transform.PatchPELinkerVersion([]byte{0x4D, 0x5A}, 14, 0); err == nil {
		t.Error("PatchPELinkerVersion on 2-byte input: want error, got nil")
	}
}

func TestPatchPELinkerVersion_RejectsELfanewOverflow(t *testing.T) {
	pe := make([]byte, 0x80)
	pe[0] = 'M'
	pe[1] = 'Z'
	binary.LittleEndian.PutUint32(pe[transform.PEELfanewOffset:transform.PEELfanewOffset+4], 0x1000)
	if err := transform.PatchPELinkerVersion(pe, 14, 0); err == nil {
		t.Error("PatchPELinkerVersion with bogus e_lfanew: want error, got nil")
	}
}

func TestRandomLinkerVersion_WithinPlausibleMSVCRange(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		major, minor := transform.RandomLinkerVersion(rng)
		if major < 12 || major > 15 {
			t.Errorf("major=%d outside [12, 15]", major)
		}
		if minor > 99 {
			t.Errorf("minor=%d outside [0, 99]", minor)
		}
	}
}

func TestRandomLinkerVersion_DeterministicGivenSeed(t *testing.T) {
	a1, a2 := transform.RandomLinkerVersion(rand.New(rand.NewSource(777)))
	b1, b2 := transform.RandomLinkerVersion(rand.New(rand.NewSource(777)))
	if a1 != b1 || a2 != b2 {
		t.Errorf("same seed produced %d.%d vs %d.%d", a1, a2, b1, b2)
	}
}

func TestRandomLinkerVersion_DiffersAcrossSeeds(t *testing.T) {
	a1, a2 := transform.RandomLinkerVersion(rand.New(rand.NewSource(1)))
	b1, b2 := transform.RandomLinkerVersion(rand.New(rand.NewSource(2)))
	if a1 == b1 && a2 == b2 {
		t.Errorf("seeds 1 and 2 collided on %d.%d", a1, a2)
	}
}
