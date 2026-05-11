package transform_test

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// peWith3DataSections returns a synthetic PE with 3 sections,
// each carrying distinct file-resident bytes ('A's, 'B's, 'C's).
// Stub-shape conventions don't apply — the helper is for the
// permutation tests and exercises the data-movement path only.
func peWith3DataSections(t *testing.T) []byte {
	t.Helper()
	const (
		peOff         = 0x40
		coffOff       = peOff + 4
		sizeOfOptHdr  = 0xF0
		optOff        = coffOff + transform.PECOFFHdrSize
		secTableOff   = optOff + sizeOfOptHdr
		numSections   = 3
		sizeOfHeaders = 0x400
		fileAlign     = 0x200
		bufSize       = 0x1000
		// Section bodies start at file 0x400, each 0x200 bytes
		// (one fileAlign block).
		secRawSize = 0x200
	)
	out := make([]byte, bufSize)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:], peOff)
	binary.LittleEndian.PutUint32(out[peOff:], 0x00004550)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFNumSectionsOffset:], numSections)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFSizeOfOptHdrOffset:], sizeOfOptHdr)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSectionAlignOffset:], 0x1000)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptFileAlignOffset:], fileAlign)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfImageOffset:], 0x4000)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfHeadersOffset:], sizeOfHeaders)

	for i, fill := range []byte{'A', 'B', 'C'} {
		hdrOff := secTableOff + i*transform.PESectionHdrSize
		copy(out[hdrOff:], []byte{'.', 's', byte('0' + i), 0, 0, 0, 0, 0})
		binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualSizeOffset:], secRawSize)
		binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualAddressOffset:], uint32(0x1000+i*0x1000))
		binary.LittleEndian.PutUint32(out[hdrOff+transform.SecSizeOfRawDataOffset:], secRawSize)
		binary.LittleEndian.PutUint32(out[hdrOff+transform.SecPointerToRawDataOffset:], uint32(0x400+i*secRawSize))
		// Stamp section body with the fill char.
		bodyOff := 0x400 + i*secRawSize
		for j := 0; j < secRawSize; j++ {
			out[bodyOff+j] = fill
		}
	}
	return out
}

func readSecHdr(t *testing.T, pe []byte, idx int) (rawOff, rawSize, va, vs uint32) {
	t.Helper()
	const (
		peOff        = 0x40
		coffOff      = peOff + 4
		sizeOfOptHdr = 0xF0
		secTableOff  = coffOff + transform.PECOFFHdrSize + sizeOfOptHdr
	)
	hdrOff := secTableOff + idx*transform.PESectionHdrSize
	rawOff = binary.LittleEndian.Uint32(pe[hdrOff+transform.SecPointerToRawDataOffset:])
	rawSize = binary.LittleEndian.Uint32(pe[hdrOff+transform.SecSizeOfRawDataOffset:])
	va = binary.LittleEndian.Uint32(pe[hdrOff+transform.SecVirtualAddressOffset:])
	vs = binary.LittleEndian.Uint32(pe[hdrOff+transform.SecVirtualSizeOffset:])
	return
}

func TestPermuteSectionFileOrder_DoesNotChangeFileSize(t *testing.T) {
	pe := peWith3DataSections(t)
	out, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 0)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder: %v", err)
	}
	if len(out) != len(pe) {
		t.Errorf("file size changed: got %d, want %d", len(out), len(pe))
	}
}

func TestPermuteSectionFileOrder_PreservesVAandVS(t *testing.T) {
	pe := peWith3DataSections(t)
	out, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 0)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder: %v", err)
	}
	for i := 0; i < 3; i++ {
		_, _, vaIn, vsIn := readSecHdr(t, pe, i)
		_, _, vaOut, vsOut := readSecHdr(t, out, i)
		if vaIn != vaOut || vsIn != vsOut {
			t.Errorf("section %d: VA/VS changed (in: 0x%x/0x%x, out: 0x%x/0x%x)",
				i, vaIn, vsIn, vaOut, vsOut)
		}
	}
}

func TestPermuteSectionFileOrder_ChangesPointerToRawData(t *testing.T) {
	pe := peWith3DataSections(t)
	out, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 0)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder: %v", err)
	}
	// At least one PointerToRawData must differ — otherwise the
	// permutation was the identity (which the function rejects
	// via re-shuffle).
	anyDiff := false
	for i := 0; i < 3; i++ {
		offIn, _, _, _ := readSecHdr(t, pe, i)
		offOut, _, _, _ := readSecHdr(t, out, i)
		if offIn != offOut {
			anyDiff = true
			break
		}
	}
	if !anyDiff {
		t.Error("permutation produced identity layout — RNG defeated the re-shuffle?")
	}
}

func TestPermuteSectionFileOrder_PreservesBodyContents(t *testing.T) {
	pe := peWith3DataSections(t)
	out, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 0)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder: %v", err)
	}
	// Each section's body, read at its NEW PointerToRawData,
	// must contain the same bytes as in the input (read at the
	// OLD PointerToRawData).
	for i, fill := range []byte{'A', 'B', 'C'} {
		offOut, sizeOut, _, _ := readSecHdr(t, out, i)
		body := out[offOut : offOut+sizeOut]
		want := bytes.Repeat([]byte{fill}, int(sizeOut))
		if !bytes.Equal(body, want) {
			t.Errorf("section %d: body content corrupted at new offset 0x%x", i, offOut)
		}
	}
}

func TestPermuteSectionFileOrder_DeterministicGivenSeed(t *testing.T) {
	a, _ := transform.PermuteSectionFileOrder(peWith3DataSections(t), rand.New(rand.NewSource(777)), 0)
	b, _ := transform.PermuteSectionFileOrder(peWith3DataSections(t), rand.New(rand.NewSource(777)), 0)
	if !bytes.Equal(a, b) {
		t.Error("same seed produced different output")
	}
}

func TestPermuteSectionFileOrder_SkipLastLeavesTailUntouched(t *testing.T) {
	pe := peWith3DataSections(t)
	out, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 1)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder(skipLast=1): %v", err)
	}
	// Section 2's PointerToRawData must be unchanged.
	offIn, _, _, _ := readSecHdr(t, pe, 2)
	offOut, _, _, _ := readSecHdr(t, out, 2)
	if offIn != offOut {
		t.Errorf("section 2 PointerToRawData = 0x%x, want 0x%x (skipLast=1)", offOut, offIn)
	}
}

func TestPermuteSectionFileOrder_FewerThan2PermutableIsNoop(t *testing.T) {
	pe := peWith3DataSections(t)
	// skipLast=2 leaves only 1 permutable section.
	out, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 2)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder: %v", err)
	}
	if !bytes.Equal(out, pe) {
		t.Error("with <2 permutable sections, output must equal input")
	}
}

// TestPermuteSectionFileOrder_UpdatesCOFFSymbolTablePointer
// guards the regression that broke debug/pe parsing when a
// section carrying the COFF symbol-table data moved: the COFF
// header's PointerToSymbolTable must be rewritten to follow the
// move, otherwise tools fail "fail to read string table".
func TestPermuteSectionFileOrder_UpdatesCOFFSymbolTablePointer(t *testing.T) {
	pe := peWith3DataSections(t)
	const (
		peOff   = 0x40
		coffOff = peOff + 4
		// Place the symbol-table pointer inside section 2 (byte fill 'C').
		// Section 2's body lives at file 0x800..0xa00.
		sec2RawOff           = 0x400 + 2*0x200
		symPtrOffsetIntoBody = 0x10
		ptrToSymTableOff     = coffOff + 0x08
	)
	binary.LittleEndian.PutUint32(pe[ptrToSymTableOff:], sec2RawOff+symPtrOffsetIntoBody)
	out, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 0)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder: %v", err)
	}
	newSec2Off, _, _, _ := readSecHdr(t, out, 2)
	wantPtr := newSec2Off + symPtrOffsetIntoBody
	gotPtr := binary.LittleEndian.Uint32(out[ptrToSymTableOff:])
	if gotPtr != wantPtr {
		t.Errorf("PointerToSymbolTable = 0x%x, want 0x%x (must follow section 2's new offset)",
			gotPtr, wantPtr)
	}
	// And the bytes at the new pointer location should still be
	// section 2's body content ('C') — proving the carrier moved
	// AND the pointer was updated to track it.
	if out[gotPtr] != 'C' {
		t.Errorf("byte at new PointerToSymbolTable = %q, want 'C' (section 2 fill)", out[gotPtr])
	}
}

func TestPermuteSectionFileOrder_DoesNotMutateInput(t *testing.T) {
	pe := peWith3DataSections(t)
	pristine := make([]byte, len(pe))
	copy(pristine, pe)
	_, err := transform.PermuteSectionFileOrder(pe, rand.New(rand.NewSource(42)), 0)
	if err != nil {
		t.Fatalf("PermuteSectionFileOrder: %v", err)
	}
	if !bytes.Equal(pe, pristine) {
		t.Error("input slice was mutated")
	}
}
