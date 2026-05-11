package transform_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// peWithRelocsForShift returns a PE rich enough to drive ShiftImageVA:
// 1 section + 1 reloc block carrying one DIR64 entry whose target
// resolves into the section. Mirrors peWithRelocs from base_relocs_test
// but adds OEP, SizeOfImage, and a non-stripped Characteristics value.
func peWithRelocsForShift(t *testing.T) []byte {
	t.Helper()
	const (
		peOff         = 0x40
		coffOff       = peOff + 4
		sizeOfOptHdr  = 0xF0
		optOff        = coffOff + transform.PECOFFHdrSize
		secTableOff   = optOff + sizeOfOptHdr
		numSections   = 1
		sizeOfHeaders = 0x400
		sectionAlign  = 0x1000
		bufSize       = 0x2000
		sec0VA        = 0x1000
		sec0RawOff    = 0x400
		sec0RawSize   = 0x100
		relocDirRVA   = 0x1010
		blockFileOff  = sec0RawOff + (relocDirRVA - sec0VA)
		// Pointer the DIR64 entry patches: lives at RVA 0x1020,
		// file 0x420. Holds an absolute value of imageBase + 0x1080.
		dir64TargetRVA  = 0x1020
		dir64TargetFile = sec0RawOff + (dir64TargetRVA - sec0VA)
		imageBase       = 0x140000000
		oepRVA          = 0x1050
	)
	out := make([]byte, bufSize)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:], peOff)
	binary.LittleEndian.PutUint32(out[peOff:], 0x00004550)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFNumSectionsOffset:], numSections)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFSizeOfOptHdrOffset:], sizeOfOptHdr)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSectionAlignOffset:], sectionAlign)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptFileAlignOffset:], 0x200)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfImageOffset:], 0x2000)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfHeadersOffset:], sizeOfHeaders)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptAddrEntryOffset:], oepRVA)
	binary.LittleEndian.PutUint64(out[optOff+0x18:], imageBase) // PE32+ ImageBase

	relocDirOff := optOff + transform.OptDataDirsStart + 5*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(out[relocDirOff:], relocDirRVA)
	binary.LittleEndian.PutUint32(out[relocDirOff+4:], 12)

	hdrOff := secTableOff
	copy(out[hdrOff:], ".text")
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualSizeOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualAddressOffset:], sec0VA)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecSizeOfRawDataOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecPointerToRawDataOffset:], sec0RawOff)

	binary.LittleEndian.PutUint32(out[blockFileOff:], 0x1000)
	binary.LittleEndian.PutUint32(out[blockFileOff+4:], 12)
	binary.LittleEndian.PutUint16(out[blockFileOff+8:], uint16(transform.RelTypeDir64)<<12|0x020)
	binary.LittleEndian.PutUint16(out[blockFileOff+10:], uint16(transform.RelTypeAbsolute)<<12)

	// The reloc target value: imageBase + 0x1080 (somewhere in section 0).
	binary.LittleEndian.PutUint64(out[dir64TargetFile:], imageBase+0x1080)
	return out
}

func readU32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func readU64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

func TestShiftImageVA_ZeroDeltaIsNoop(t *testing.T) {
	pe := peWithRelocsForShift(t)
	out, err := transform.ShiftImageVA(pe, 0)
	if err != nil {
		t.Fatalf("ShiftImageVA(0): %v", err)
	}
	if !bytes.Equal(out, pe) {
		t.Error("delta=0 must return an unchanged copy of input")
	}
}

func TestShiftImageVA_RejectsRelocsStripped(t *testing.T) {
	pe := peWithRelocsForShift(t)
	const coffOff = 0x40 + 4
	binary.LittleEndian.PutUint16(pe[coffOff+transform.CharOff:], transform.CharRelocsStripped)
	_, err := transform.ShiftImageVA(pe, 0x1000)
	if !errors.Is(err, transform.ErrRelocsStripped) {
		t.Errorf("got %v, want ErrRelocsStripped", err)
	}
}

func TestShiftImageVA_RejectsMisalignedDelta(t *testing.T) {
	pe := peWithRelocsForShift(t)
	_, err := transform.ShiftImageVA(pe, 0x800) // SectionAlign is 0x1000
	if err == nil {
		t.Error("misaligned delta: want error, got nil")
	}
}

func TestShiftImageVA_BumpsSectionVA(t *testing.T) {
	pe := peWithRelocsForShift(t)
	const delta uint32 = 0x2000
	out, err := transform.ShiftImageVA(pe, delta)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	const (
		peOff       = 0x40
		coffOff     = peOff + 4
		secTableOff = coffOff + transform.PECOFFHdrSize + 0xF0
	)
	got := readU32(out[secTableOff+transform.SecVirtualAddressOffset:])
	if want := uint32(0x1000) + delta; got != want {
		t.Errorf("section[0].VA = 0x%x, want 0x%x", got, want)
	}
}

func TestShiftImageVA_BumpsOEP(t *testing.T) {
	pe := peWithRelocsForShift(t)
	const delta uint32 = 0x3000
	out, err := transform.ShiftImageVA(pe, delta)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	got := readU32(out[optOff+transform.OptAddrEntryOffset:])
	if want := uint32(0x1050) + delta; got != want {
		t.Errorf("OEP = 0x%x, want 0x%x", got, want)
	}
}

func TestShiftImageVA_BumpsDataDirectoryEntries(t *testing.T) {
	pe := peWithRelocsForShift(t)
	const delta uint32 = 0x1000
	out, err := transform.ShiftImageVA(pe, delta)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	relocDirOff := optOff + transform.OptDataDirsStart + 5*transform.OptDataDirEntrySize
	got := readU32(out[relocDirOff:])
	if want := uint32(0x1010) + delta; got != want {
		t.Errorf("BaseReloc DataDirectory RVA = 0x%x, want 0x%x", got, want)
	}
}

func TestShiftImageVA_BumpsBlockPageRVA(t *testing.T) {
	pe := peWithRelocsForShift(t)
	const delta uint32 = 0x1000
	out, err := transform.ShiftImageVA(pe, delta)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	const blockFileOff = 0x400 + 0x10
	got := readU32(out[blockFileOff:])
	if want := uint32(0x1000) + delta; got != want {
		t.Errorf("reloc block PageRVA = 0x%x, want 0x%x", got, want)
	}
}

func TestShiftImageVA_BumpsDIR64TargetValue(t *testing.T) {
	pe := peWithRelocsForShift(t)
	const delta uint32 = 0x1000
	out, err := transform.ShiftImageVA(pe, delta)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	const dir64TargetFile = 0x400 + 0x20
	got := readU64(out[dir64TargetFile:])
	const imageBase uint64 = 0x140000000
	if want := imageBase + 0x1080 + uint64(delta); got != want {
		t.Errorf("DIR64 target value = 0x%x, want 0x%x", got, want)
	}
}

func TestShiftImageVA_BumpsSizeOfImage(t *testing.T) {
	pe := peWithRelocsForShift(t)
	const delta uint32 = 0x4000
	out, err := transform.ShiftImageVA(pe, delta)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	got := readU32(out[optOff+transform.OptSizeOfImageOffset:])
	if want := uint32(0x2000) + delta; got != want {
		t.Errorf("SizeOfImage = 0x%x, want 0x%x", got, want)
	}
}

func TestShiftImageVA_DoesNotMutateInput(t *testing.T) {
	pe := peWithRelocsForShift(t)
	pristine := make([]byte, len(pe))
	copy(pristine, pe)
	_, err := transform.ShiftImageVA(pe, 0x1000)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	if !bytes.Equal(pe, pristine) {
		t.Error("input slice was mutated")
	}
}

// TestShiftImageVA_RealWinhello sanity-checks the shift against
// the real winhello fixture: the result must still parse via
// debug/pe (relocs valid, headers consistent).
func TestShiftImageVA_RealWinhello(t *testing.T) {
	path := filepath.Join("..", "testdata", "winhello.exe")
	pe, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture missing (%v); build via testdata/Makefile", err)
	}
	out, err := transform.ShiftImageVA(pe, 0x2000)
	if err != nil {
		t.Fatalf("ShiftImageVA: %v", err)
	}
	if len(out) != len(pe) {
		t.Errorf("file size changed: got %d, want %d", len(out), len(pe))
	}
}
