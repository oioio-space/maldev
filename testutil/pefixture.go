package testutil

import (
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// BuildDLLWithReloc returns an in-memory synthetic Windows DLL
// fixture for the packer DLL test suite. The output:
//   - is a PE32+ with IMAGE_FILE_DLL set in COFF Characteristics,
//   - has a single .text section of `bodySize` bytes containing
//     `0xC3` (RET) at every byte — executable nonsense, but the
//     pack pipeline never executes it,
//   - declares OEP at .text RVA (so [transform.PlanDLL] accepts
//     the entry point as inside .text),
//   - has a populated BASERELOC table with one DIR64 entry pointing
//     at a fake pointer at `textRVA + 0x10`. The non-empty reloc
//     directory unblocks [transform.InjectStubDLL]
//     (which refuses BASERELOC-less inputs to avoid producing
//     partially-relocatable output).
//
// `bodySize` should be ≥ 0x10 so the synthetic reloc target lands
// inside .text. Pass 0x100 for a non-trivial pack-time payload,
// or 1 for a minimal fixture in admission tests.
//
// Shared between transform's inject_dll_test.go and packer's
// packer_dll_test.go so the two suites don't drift on the
// fixture's PE layout (the /simplify pass after slice 4 flagged
// near-duplicate hand-rolled fixtures in each test file).
func BuildDLLWithReloc(t *testing.T, bodySize int) []byte {
	t.Helper()
	body := make([]byte, bodySize)
	for i := range body {
		body[i] = 0xC3
	}
	base, err := transform.BuildMinimalPE32Plus(body)
	if err != nil {
		t.Fatalf("testutil: BuildMinimalPE32Plus: %v", err)
	}

	peOff := binary.LittleEndian.Uint32(base[transform.PEELfanewOffset:])
	coffOff := peOff + transform.PESignatureSize
	optOff := coffOff + transform.PECOFFHdrSize

	// IMAGE_FILE_DLL bit.
	c := binary.LittleEndian.Uint16(base[coffOff+0x12:])
	binary.LittleEndian.PutUint16(base[coffOff+0x12:], c|transform.ImageFileDLL)

	// One DIR64 reloc entry covering textRVA+0x10.
	textRVA := binary.LittleEndian.Uint32(base[optOff+transform.OptAddrEntryOffset:])
	targetRVA := textRVA + 0x10
	pageRVA := targetRVA &^ 0xFFF
	entry := (transform.RelTypeDir64 << 12) | uint16(targetRVA&0x0FFF)

	const blockSize = 12
	relocBytes := make([]byte, blockSize)
	binary.LittleEndian.PutUint32(relocBytes[0:], pageRVA)
	binary.LittleEndian.PutUint32(relocBytes[4:], blockSize)
	binary.LittleEndian.PutUint16(relocBytes[8:], entry)
	binary.LittleEndian.PutUint16(relocBytes[10:], 0) // RelTypeAbsolute padding

	fileAlign := binary.LittleEndian.Uint32(base[optOff+transform.OptFileAlignOffset:])
	sectionAlign := binary.LittleEndian.Uint32(base[optOff+transform.OptSectionAlignOffset:])
	sizeOfImage := binary.LittleEndian.Uint32(base[optOff+transform.OptSizeOfImageOffset:])

	relocRVA := transform.AlignUpU32(sizeOfImage, sectionAlign)
	relocFileOff := transform.AlignUpU32(uint32(len(base)), fileAlign)
	relocFileSize := transform.AlignUpU32(uint32(len(relocBytes)), fileAlign)

	out := make([]byte, relocFileOff+relocFileSize)
	copy(out, base)
	copy(out[relocFileOff:], relocBytes)

	// Append .reloc section header.
	sizeOfOptHdr := binary.LittleEndian.Uint16(base[coffOff+transform.COFFSizeOfOptHdrOffset:])
	numSections := binary.LittleEndian.Uint16(base[coffOff+transform.COFFNumSectionsOffset:])
	hdrOff := optOff + uint32(sizeOfOptHdr) + uint32(numSections)*transform.PESectionHdrSize
	copy(out[hdrOff:hdrOff+8], []byte(".reloc\x00\x00"))
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualSizeOffset:], uint32(len(relocBytes)))
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualAddressOffset:], relocRVA)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecSizeOfRawDataOffset:], relocFileSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecPointerToRawDataOffset:], relocFileOff)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecCharacteristicsOffset:], transform.ScnMemReadInitData)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFNumSectionsOffset:], numSections+1)

	// Update DataDirectory[BASERELOC] (index transform.DirBaseReloc) + SizeOfImage.
	dirOff := optOff + transform.OptDataDirsStart + transform.DirBaseReloc*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(out[dirOff:], relocRVA)
	binary.LittleEndian.PutUint32(out[dirOff+4:], uint32(len(relocBytes)))
	newSizeOfImage := transform.AlignUpU32(relocRVA+uint32(len(relocBytes)), sectionAlign)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfImageOffset:], newSizeOfImage)

	return out
}
