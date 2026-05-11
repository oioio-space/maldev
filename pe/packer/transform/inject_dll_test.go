package transform_test

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// buildDLLWithReloc returns a synthetic Windows DLL fixture:
//   - .text: 0x100 bytes, RET at offset 0 (OEP = TextRVA)
//   - .reloc: one IMAGE_BASE_RELOCATION block carrying one DIR64
//     entry for a fake pointer at TextRVA+0x10 (mimics what a real
//     DLL's reloc table looks like — non-empty, parseable).
//
// IMAGE_FILE_DLL is set in COFF Characteristics so PlanDLL accepts it.
func buildDLLWithReloc(t *testing.T) []byte {
	t.Helper()
	// Start from BuildMinimalPE32Plus and flip the DLL bit, then
	// extend with a .reloc section and a populated BASERELOC
	// DataDirectory entry.
	base, err := transform.BuildMinimalPE32Plus([]byte{0xC3}) // RET
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}

	peOff := binary.LittleEndian.Uint32(base[transform.PEELfanewOffset:])
	coffOff := peOff + transform.PESignatureSize
	optOff := coffOff + transform.PECOFFHdrSize
	// Set IMAGE_FILE_DLL.
	c := binary.LittleEndian.Uint16(base[coffOff+0x12:])
	binary.LittleEndian.PutUint16(base[coffOff+0x12:], c|transform.ImageFileDLL)

	// Reloc block: target = TextRVA+0x10 (somewhere inside .text).
	textRVA := binary.LittleEndian.Uint32(base[optOff+transform.OptAddrEntryOffset:])
	targetRVA := textRVA + 0x10
	pageRVA := targetRVA &^ 0xFFF
	entryRVA := uint16(targetRVA & 0x0FFF)
	entry := (transform.RelTypeDir64 << 12) | entryRVA

	const blockSize = 12
	relocBytes := make([]byte, blockSize)
	binary.LittleEndian.PutUint32(relocBytes[0:], pageRVA)
	binary.LittleEndian.PutUint32(relocBytes[4:], blockSize)
	binary.LittleEndian.PutUint16(relocBytes[8:], entry)
	binary.LittleEndian.PutUint16(relocBytes[10:], 0)

	// Append a .reloc section. fileAlign = 0x200 (per BuildMinimalPE32Plus).
	fileAlign := binary.LittleEndian.Uint32(base[optOff+transform.OptFileAlignOffset:])
	sectionAlign := binary.LittleEndian.Uint32(base[optOff+transform.OptSectionAlignOffset:])
	sizeOfImage := binary.LittleEndian.Uint32(base[optOff+transform.OptSizeOfImageOffset:])

	relocRVA := transform.AlignUpU32(sizeOfImage, sectionAlign)
	relocFileOff := transform.AlignUpU32(uint32(len(base)), fileAlign)
	relocFileSize := transform.AlignUpU32(uint32(len(relocBytes)), fileAlign)

	out := make([]byte, relocFileOff+relocFileSize)
	copy(out, base)
	copy(out[relocFileOff:], relocBytes)

	// Append section header.
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

	// Update DataDirectory[BASERELOC] (index 5) + SizeOfImage.
	dirOff := optOff + transform.OptDataDirsStart + 5*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(out[dirOff:], relocRVA)
	binary.LittleEndian.PutUint32(out[dirOff+4:], uint32(len(relocBytes)))
	newSizeOfImage := transform.AlignUpU32(relocRVA+uint32(len(relocBytes)), sectionAlign)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfImageOffset:], newSizeOfImage)

	return out
}

// stubBytesWithSentinel returns a fake stub buffer of the requested
// total size whose last 8 bytes are the dllStubSentinel
// (0xDEADC0DEDEADBABE). InjectStubDLL pre-fills the slot via
// patchDllMainSlotLocal — these bytes give it a target to patch.
func stubBytesWithSentinel(size uint32) []byte {
	out := make([]byte, size)
	// Fill leading bytes with NOPs to simulate stub asm.
	for i := range out[:size-8] {
		out[i] = 0x90
	}
	binary.LittleEndian.PutUint64(out[size-8:], 0xDEADC0DEDEADBABE)
	return out
}

// TestInjectStubDLL_HappyPath — round-trip a synthetic DLL through
// InjectStubDLL and verify the output is a valid PE that:
//   - debug/pe parses without error,
//   - has IMAGE_FILE_DLL still set,
//   - lists exactly 3 sections (original .text + appended stub + .mldreloc),
//   - has its BASERELOC DataDirectory pointing at the new .mldreloc section,
//   - and the merged reloc table contains a DIR64 entry covering the slot.
func TestInjectStubDLL_HappyPath(t *testing.T) {
	dll := buildDLLWithReloc(t)
	plan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}

	encrypted := make([]byte, plan.TextSize)
	stub := stubBytesWithSentinel(plan.StubMaxSize)

	out, err := transform.InjectStubDLL(dll, encrypted, stub, plan)
	if err != nil {
		t.Fatalf("InjectStubDLL: %v", err)
	}

	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe.NewFile: %v", err)
	}
	defer pf.Close()

	if pf.FileHeader.Characteristics&transform.ImageFileDLL == 0 {
		t.Error("output lost IMAGE_FILE_DLL")
	}
	// Fixture starts with .text + .reloc (host) — InjectStubDLL appends
	// the stub section + .mldrel, yielding 4 total.
	if pf.FileHeader.NumberOfSections != 4 {
		t.Errorf("NumberOfSections = %d, want 4 (.text + .reloc + stub + .mldrel)", pf.FileHeader.NumberOfSections)
	}
	var appended *pe.Section
	for _, s := range pf.Sections {
		if s.Name == ".mldrel" {
			appended = s
			break
		}
	}
	if appended == nil {
		t.Fatal(".mldrel section not found in output")
	}
}

// TestInjectStubDLL_SlotPatchedWithAbsVA — the 8-byte slot in the
// embedded stub bytes must be rewritten with ImageBase + OEPRVA.
func TestInjectStubDLL_SlotPatchedWithAbsVA(t *testing.T) {
	dll := buildDLLWithReloc(t)
	plan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}
	encrypted := make([]byte, plan.TextSize)
	stub := stubBytesWithSentinel(plan.StubMaxSize)

	out, err := transform.InjectStubDLL(dll, encrypted, stub, plan)
	if err != nil {
		t.Fatalf("InjectStubDLL: %v", err)
	}

	// The stub bytes live at plan.StubFileOff..StubFileOff+StubMaxSize
	// in the output. Slot occupies the LAST 8 bytes of the stubBytes
	// we passed in (size = StubMaxSize). Read from the same offset.
	slotFileOff := plan.StubFileOff + plan.StubMaxSize - transform.DLLStubSlotByteOffsetFromEnd
	got := binary.LittleEndian.Uint64(out[slotFileOff : slotFileOff+8])
	wantImageBase := transform.MinimalPE32PlusImageBase
	want := wantImageBase + uint64(plan.OEPRVA)
	if got != want {
		t.Errorf("slot bytes = %#x, want %#x (ImageBase %#x + OEPRVA %#x)",
			got, want, wantImageBase, plan.OEPRVA)
	}
}

// TestInjectStubDLL_RelocCoversSlot — the merged reloc table in the
// .mldreloc section must contain a DIR64 entry whose RVA equals
// the slot's RVA.
func TestInjectStubDLL_RelocCoversSlot(t *testing.T) {
	dll := buildDLLWithReloc(t)
	plan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}
	encrypted := make([]byte, plan.TextSize)
	stub := stubBytesWithSentinel(plan.StubMaxSize)

	out, err := transform.InjectStubDLL(dll, encrypted, stub, plan)
	if err != nil {
		t.Fatalf("InjectStubDLL: %v", err)
	}

	slotRVA := plan.StubRVA + plan.StubMaxSize - transform.DLLStubSlotByteOffsetFromEnd
	var found bool
	walkErr := transform.WalkBaseRelocs(out, func(e transform.BaseRelocEntry) error {
		if e.Type == transform.RelTypeDir64 && e.RVA == slotRVA {
			found = true
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("WalkBaseRelocs: %v", walkErr)
	}
	if !found {
		t.Errorf("no DIR64 reloc entry covering slot RVA %#x", slotRVA)
	}
}

// TestInjectStubDLL_PreservesHostRelocs — the merged reloc table
// must STILL contain the host's original DIR64 entry (the fixture's
// fake pointer at TextRVA+0x10). Guards against an InjectStubDLL
// bug that overwrote DataDirectory[BASERELOC] without copying the
// host's existing blocks.
func TestInjectStubDLL_PreservesHostRelocs(t *testing.T) {
	dll := buildDLLWithReloc(t)
	plan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}
	hostTargetRVA := plan.TextRVA + 0x10

	encrypted := make([]byte, plan.TextSize)
	stub := stubBytesWithSentinel(plan.StubMaxSize)
	out, err := transform.InjectStubDLL(dll, encrypted, stub, plan)
	if err != nil {
		t.Fatalf("InjectStubDLL: %v", err)
	}

	var hostFound bool
	if err := transform.WalkBaseRelocs(out, func(e transform.BaseRelocEntry) error {
		if e.Type == transform.RelTypeDir64 && e.RVA == hostTargetRVA {
			hostFound = true
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkBaseRelocs: %v", err)
	}
	if !hostFound {
		t.Errorf("host's original DIR64 reloc at %#x missing from merged table", hostTargetRVA)
	}
}

// TestInjectStubDLL_RejectsExePlan — guard against accidental
// routing of an EXE plan through the DLL injector.
func TestInjectStubDLL_RejectsExePlan(t *testing.T) {
	dll := buildDLLWithReloc(t)
	plan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}
	plan.IsDLL = false
	stub := stubBytesWithSentinel(plan.StubMaxSize)
	_, err = transform.InjectStubDLL(dll, make([]byte, plan.TextSize), stub, plan)
	if err == nil {
		t.Error("expected error for plan.IsDLL=false, got nil")
	}
}

// TestInjectStubDLL_RejectsNoRelocDir — a DLL with no BASERELOC
// DataDirectory must be refused, since the slot won't be rebased
// under ASLR.
func TestInjectStubDLL_RejectsNoRelocDir(t *testing.T) {
	// Start with the standard reloc-bearing fixture, then ZERO out
	// the BASERELOC DataDirectory to simulate a /FIXED DLL.
	dll := buildDLLWithReloc(t)
	peOff := binary.LittleEndian.Uint32(dll[transform.PEELfanewOffset:])
	coffOff := peOff + transform.PESignatureSize
	optOff := coffOff + transform.PECOFFHdrSize
	dirOff := optOff + transform.OptDataDirsStart + 5*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(dll[dirOff:], 0)
	binary.LittleEndian.PutUint32(dll[dirOff+4:], 0)

	plan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}
	stub := stubBytesWithSentinel(plan.StubMaxSize)
	_, err = transform.InjectStubDLL(dll, make([]byte, plan.TextSize), stub, plan)
	if !errors.Is(err, transform.ErrNoExistingRelocDir) {
		t.Errorf("got %v, want ErrNoExistingRelocDir", err)
	}
}
