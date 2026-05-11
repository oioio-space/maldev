package transform_test

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// minPEWithASLR returns a synthetic PE buffer with a properly-
// sized Optional Header (0xF0 bytes) and the DYNAMIC_BASE bit
// set in DllCharacteristics — both required by PatchPEImageBase.
func minPEWithASLR(t *testing.T) []byte {
	t.Helper()
	const (
		peOff   = 0x40
		coffOff = peOff + 4
		optOff  = coffOff + transform.PECOFFHdrSize
	)
	pe := make([]byte, 0x200)
	pe[0] = 'M'
	pe[1] = 'Z'
	binary.LittleEndian.PutUint32(pe[transform.PEELfanewOffset:], peOff)
	binary.LittleEndian.PutUint32(pe[peOff:], 0x00004550)
	binary.LittleEndian.PutUint16(pe[coffOff+transform.COFFSizeOfOptHdrOffset:], 0xF0)
	binary.LittleEndian.PutUint16(pe[optOff+transform.OptDllCharacteristicsOffset:],
		transform.DllCharDynamicBase)
	return pe
}

func TestPatchPEImageBase_WritesAtCorrectOffset(t *testing.T) {
	pe := minPEWithASLR(t)
	const want uint64 = 0x140123456000
	if err := transform.PatchPEImageBase(pe, want); err != nil {
		t.Fatalf("PatchPEImageBase: %v", err)
	}
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	got := binary.LittleEndian.Uint64(pe[optOff+transform.OptImageBase64Offset:])
	if got != want {
		t.Errorf("ImageBase = 0x%x, want 0x%x", got, want)
	}
}

func TestPatchPEImageBase_RejectsTruncated(t *testing.T) {
	if err := transform.PatchPEImageBase([]byte{0x4D, 0x5A}, 0); err == nil {
		t.Error("PatchPEImageBase on 2-byte input: want error, got nil")
	}
}

func TestPatchPEImageBase_RejectsNonASLR(t *testing.T) {
	pe := minPEWithASLR(t)
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	// Clear the DYNAMIC_BASE bit.
	binary.LittleEndian.PutUint16(pe[optOff+transform.OptDllCharacteristicsOffset:], 0)
	if err := transform.PatchPEImageBase(pe, 0x140000000); err == nil {
		t.Error("PE without DYNAMIC_BASE: want error, got nil")
	}
}

func TestRandomImageBase64_AlignedAndInRange(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 100; i++ {
		b := transform.RandomImageBase64(rng)
		if b%transform.RandomImageBaseAlignment != 0 {
			t.Errorf("ImageBase 0x%x not %d-aligned", b, transform.RandomImageBaseAlignment)
		}
		if b < 0x140000000 || b >= 0x7FF000000000 {
			t.Errorf("ImageBase 0x%x outside expected range", b)
		}
	}
}

func TestRandomImageBase64_DeterministicGivenSeed(t *testing.T) {
	a := transform.RandomImageBase64(rand.New(rand.NewSource(777)))
	b := transform.RandomImageBase64(rand.New(rand.NewSource(777)))
	if a != b {
		t.Errorf("same seed produced 0x%x vs 0x%x", a, b)
	}
}

func TestRandomImageBase64_DiffersAcrossSeeds(t *testing.T) {
	a := transform.RandomImageBase64(rand.New(rand.NewSource(1)))
	b := transform.RandomImageBase64(rand.New(rand.NewSource(2)))
	if a == b {
		t.Errorf("seeds 1 and 2 collided on 0x%x", a)
	}
}
