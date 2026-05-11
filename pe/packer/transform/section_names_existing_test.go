package transform_test

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// pe3Sections returns a synthetic PE buffer with three section
// headers carrying recognisable names (".text\0\0\0", ".data\0\0\0",
// ".rdata\0\0"). Just enough header to drive
// RandomizeExistingSectionNames; section bodies are not present
// (the function only walks headers).
func pe3Sections(t *testing.T) []byte {
	t.Helper()
	const (
		peOff           = 0x40
		coffOff         = peOff + 4
		sizeOfOptHdr    = 0xF0
		optOff          = coffOff + transform.PECOFFHdrSize
		secTableOff     = optOff + sizeOfOptHdr
		numSections     = 3
		bufSize         = secTableOff + numSections*transform.PESectionHdrSize + 0x20
	)
	out := make([]byte, bufSize)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:transform.PEELfanewOffset+4], peOff)
	binary.LittleEndian.PutUint32(out[peOff:peOff+4], 0x00004550) // "PE\0\0"
	binary.LittleEndian.PutUint16(
		out[coffOff+transform.COFFNumSectionsOffset:coffOff+transform.COFFNumSectionsOffset+2],
		numSections)
	binary.LittleEndian.PutUint16(
		out[coffOff+transform.COFFSizeOfOptHdrOffset:coffOff+transform.COFFSizeOfOptHdrOffset+2],
		sizeOfOptHdr)
	copy(out[secTableOff+0*transform.PESectionHdrSize:], []byte(".text\x00\x00\x00"))
	copy(out[secTableOff+1*transform.PESectionHdrSize:], []byte(".data\x00\x00\x00"))
	copy(out[secTableOff+2*transform.PESectionHdrSize:], []byte(".rdata\x00\x00"))
	return out
}

func readSecName(t *testing.T, pe []byte, idx int) [8]byte {
	t.Helper()
	const (
		peOff       = 0x40
		coffOff     = peOff + 4
		sizeOfOptHdr = 0xF0
		secTableOff = coffOff + transform.PECOFFHdrSize + sizeOfOptHdr
	)
	hdrOff := secTableOff + idx*transform.PESectionHdrSize
	var name [8]byte
	copy(name[:], pe[hdrOff:hdrOff+8])
	return name
}

func TestRandomizeExistingSectionNames_OverwritesEveryName(t *testing.T) {
	pe := pe3Sections(t)
	rng := rand.New(rand.NewSource(42))
	if err := transform.RandomizeExistingSectionNames(pe, rng, 0); err != nil {
		t.Fatalf("RandomizeExistingSectionNames: %v", err)
	}
	for i := 0; i < 3; i++ {
		got := readSecName(t, pe, i)
		if got[0] != '.' {
			t.Errorf("section %d: name[0] = %q, want '.'", i, got[0])
		}
		for j := 1; j <= 5; j++ {
			if got[j] < 'a' || got[j] > 'z' {
				t.Errorf("section %d: name[%d] = %q, want lowercase letter", i, j, got[j])
			}
		}
		if got[6] != 0 || got[7] != 0 {
			t.Errorf("section %d: trailing %02x %02x, want NUL pad", i, got[6], got[7])
		}
	}
}

func TestRandomizeExistingSectionNames_ProducesDistinctNames(t *testing.T) {
	pe := pe3Sections(t)
	if err := transform.RandomizeExistingSectionNames(pe, rand.New(rand.NewSource(1)), 0); err != nil {
		t.Fatalf("RandomizeExistingSectionNames: %v", err)
	}
	a, b, c := readSecName(t, pe, 0), readSecName(t, pe, 1), readSecName(t, pe, 2)
	if a == b || b == c || a == c {
		t.Errorf("collision: %q %q %q", string(a[:]), string(b[:]), string(c[:]))
	}
}

func TestRandomizeExistingSectionNames_DeterministicGivenSeed(t *testing.T) {
	a := pe3Sections(t)
	b := pe3Sections(t)
	if err := transform.RandomizeExistingSectionNames(a, rand.New(rand.NewSource(777)), 0); err != nil {
		t.Fatalf("randomize a: %v", err)
	}
	if err := transform.RandomizeExistingSectionNames(b, rand.New(rand.NewSource(777)), 0); err != nil {
		t.Fatalf("randomize b: %v", err)
	}
	for i := 0; i < 3; i++ {
		if readSecName(t, a, i) != readSecName(t, b, i) {
			t.Errorf("section %d: same seed produced different names", i)
		}
	}
}

func TestRandomizeExistingSectionNames_SkipLastPreservesTrailingNames(t *testing.T) {
	pe := pe3Sections(t)
	originalLast := readSecName(t, pe, 2)
	if err := transform.RandomizeExistingSectionNames(pe, rand.New(rand.NewSource(42)), 1); err != nil {
		t.Fatalf("RandomizeExistingSectionNames(skipLast=1): %v", err)
	}
	gotLast := readSecName(t, pe, 2)
	if gotLast != originalLast {
		t.Errorf("section 2 (last) was renamed despite skipLast=1: got %q, want %q",
			string(gotLast[:]), string(originalLast[:]))
	}
	if readSecName(t, pe, 0) == ([8]byte{'.', 't', 'e', 'x', 't', 0, 0, 0}) {
		t.Error("section 0 was NOT renamed despite skipLast=1 only exempting the tail")
	}
}

func TestRandomizeExistingSectionNames_RejectsBadSkipLast(t *testing.T) {
	pe := pe3Sections(t)
	if err := transform.RandomizeExistingSectionNames(pe, rand.New(rand.NewSource(1)), -1); err == nil {
		t.Error("skipLast=-1: want error, got nil")
	}
	if err := transform.RandomizeExistingSectionNames(pe, rand.New(rand.NewSource(1)), 99); err == nil {
		t.Error("skipLast > NumberOfSections: want error, got nil")
	}
}

func TestRandomizeExistingSectionNames_RejectsTruncated(t *testing.T) {
	if err := transform.RandomizeExistingSectionNames([]byte{0x4D, 0x5A}, rand.New(rand.NewSource(1)), 0); err == nil {
		t.Error("RandomizeExistingSectionNames on 2-byte input: want error, got nil")
	}
}

// TestRandomizeExistingSectionNames_PreservesVirtualAddresses
// guards the loader contract: rename must touch only the 8-byte
// Name slot, never the VirtualAddress field that follows.
func TestRandomizeExistingSectionNames_PreservesVirtualAddresses(t *testing.T) {
	pe := pe3Sections(t)
	const (
		peOff        = 0x40
		coffOff      = peOff + 4
		sizeOfOptHdr = 0xF0
		secTableOff  = coffOff + transform.PECOFFHdrSize + sizeOfOptHdr
	)
	for i := 0; i < 3; i++ {
		hdrOff := secTableOff + i*transform.PESectionHdrSize
		binary.LittleEndian.PutUint32(
			pe[hdrOff+transform.SecVirtualAddressOffset:hdrOff+transform.SecVirtualAddressOffset+4],
			uint32(0x10000+i*0x1000))
	}
	if err := transform.RandomizeExistingSectionNames(pe, rand.New(rand.NewSource(42)), 0); err != nil {
		t.Fatalf("RandomizeExistingSectionNames: %v", err)
	}
	for i := 0; i < 3; i++ {
		hdrOff := secTableOff + i*transform.PESectionHdrSize
		va := binary.LittleEndian.Uint32(
			pe[hdrOff+transform.SecVirtualAddressOffset : hdrOff+transform.SecVirtualAddressOffset+4])
		if want := uint32(0x10000 + i*0x1000); va != want {
			t.Errorf("section %d VA = 0x%x after rename, want 0x%x", i, va, want)
		}
	}
}
