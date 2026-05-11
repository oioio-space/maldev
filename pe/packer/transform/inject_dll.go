package transform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// SetIMAGEFILEDLL flips the IMAGE_FILE_DLL bit in the COFF
// Characteristics field of a PE32+ buffer. OR-only: any other
// flags (EXECUTABLE_IMAGE, LARGE_ADDRESS_AWARE, …) are preserved.
//
// Used by [InjectConvertedDLL] in production and by test fixtures
// that need to synthesise a DLL from a minimal EXE template
// (`testutil.BuildDLLWithReloc`, `plan_dll_test.setDLLBit`).
// Centralising the byte math here avoids drift across 3 sites.
//
// Returns an error if the buffer is too short to carry a valid PE
// header — caller-owned validation rather than a silent no-op.
func SetIMAGEFILEDLL(buf []byte) error {
	if len(buf) < int(PEELfanewOffset)+4 {
		return fmt.Errorf("transform: SetIMAGEFILEDLL: buffer too short for e_lfanew")
	}
	peOff := binary.LittleEndian.Uint32(buf[PEELfanewOffset:])
	coffOff := peOff + PESignatureSize
	charsOff := coffOff + 0x12
	if int(charsOff)+2 > len(buf) {
		return fmt.Errorf("transform: SetIMAGEFILEDLL: buffer too short for COFF Characteristics")
	}
	chars := binary.LittleEndian.Uint16(buf[charsOff:])
	binary.LittleEndian.PutUint16(buf[charsOff:], chars|ImageFileDLL)
	return nil
}

// IsDLL reports whether `input` is a PE32+ with IMAGE_FILE_DLL set
// in COFF Characteristics. Returns false (no error) when the input
// is not a PE at all, when it's too short, or when the bit is clear.
//
// Cheap pre-flight for dispatchers that need to pick between
// [PlanPE] (EXE path) and [PlanDLL] (DLL path) without paying the
// full Plan computation.
func IsDLL(input []byte) bool {
	if DetectFormat(input) != FormatPE {
		return false
	}
	if len(input) < int(PEELfanewOffset)+4 {
		return false
	}
	peOff := binary.LittleEndian.Uint32(input[PEELfanewOffset:])
	coffOff := peOff + PESignatureSize
	if int(coffOff)+PECOFFHdrSize > len(input) {
		return false
	}
	c := binary.LittleEndian.Uint16(input[coffOff+0x12:])
	return c&ImageFileDLL != 0
}

// DLLStubSlotByteOffsetFromEnd is the byte offset (counted from
// the end of [stage1.EmitDLLStub]'s output) where the 8-byte
// orig_dllmain_slot lives. The slot always sits at the very end:
// 1-byte decrypted_flag at -9, 8-byte slot at -8.
const DLLStubSlotByteOffsetFromEnd = 8

// DLLStubSentinel is the 8-byte placeholder [stage1.EmitDLLStub]
// bakes into the orig_dllmain_slot. [PatchDLLStubSlot] (and its
// stage1 wrapper) replaces it with the absolute VA of the original
// DllMain at pack time.
//
// Exported from transform so stage1 (which imports transform for
// [Plan]) can consume the same constant without a duplicate
// declaration — kills the drift hazard the v0.111.0 review flagged.
const DLLStubSentinel uint64 = 0xDEADC0DEDEADBABE

// DLLStubSentinelBytes is [DLLStubSentinel] in little-endian wire form.
var DLLStubSentinelBytes = binary.LittleEndian.AppendUint64(nil, DLLStubSentinel)

// defaultStubSectionName + defaultRelocSectionName are the 8-byte
// labels written by [InjectStubDLL] when the operator doesn't
// override them via [Plan.StubSectionName]. PE section names are
// fixed-width 8 bytes; the trailing zeros come from the [8]byte
// zero-value.
var (
	defaultStubSectionName  = [8]byte{'.', 'm', 'l', 'd', 'v'}
	defaultRelocSectionName = [8]byte{'.', 'm', 'l', 'd', 'r', 'e', 'l'}
)

// ErrNoExistingRelocDir fires when InjectStubDLL receives a PE
// whose BASERELOC DataDirectory is empty — without an existing
// reloc table, the new DIR64 entry the injector wants to add
// would be the only one and ASLR would leave host pointers
// unrelocated. In practice every modern compiler emits a reloc
// table for DLLs, so this rejection catches malformed inputs.
var ErrNoExistingRelocDir = errors.New("transform: DLL has no BASERELOC directory — refusing to inject reloc-dependent stub")

// ErrDLLStubSlotNotFound / ErrDLLStubSlotDuplicate surface from
// [PatchDLLStubSlot] when the [DLLStubSentinel] placeholder is
// missing or appears more than once.
var (
	ErrDLLStubSlotNotFound  = errors.New("transform: DllMain slot sentinel not found in stubBytes")
	ErrDLLStubSlotDuplicate = errors.New("transform: DllMain slot sentinel matched more than once")
)

// PatchDLLStubSlot rewrites the [DLLStubSentinel] placeholder in
// stubBytes with absVA (= imageBase + OEPRVA), returning the
// byte offset where the slot lived. Two-pass scan so a uniqueness
// violation leaves the buffer untouched.
//
// **Caller invariant:** stubBytes must be the stub slice ONLY,
// before any concatenation with an SGN-encoded payload — a chance
// payload collision with the sentinel would otherwise corrupt
// payload bytes.
func PatchDLLStubSlot(stubBytes []byte, absVA uint64) (int, error) {
	first := -1
	count := 0
	off := 0
	for {
		i := bytes.Index(stubBytes[off:], DLLStubSentinelBytes)
		if i < 0 {
			break
		}
		i += off
		if first < 0 {
			first = i
		}
		count++
		off = i + 8
	}
	switch {
	case count == 0:
		return 0, ErrDLLStubSlotNotFound
	case count > 1:
		return 0, ErrDLLStubSlotDuplicate
	}
	binary.LittleEndian.PutUint64(stubBytes[first:first+8], absVA)
	return first, nil
}

// InjectStubDLL is the DLL counterpart of [InjectStubPE]. It does
// everything InjectStubPE does (overwrite .text with the encrypted
// payload, mark .text RWX, append a stub section, rewrite OEP to
// the stub) PLUS:
//
//  1. Pre-fills the stub's 8-byte orig_dllmain_slot with the
//     absolute VA of the original DllMain (ImageBase + plan.OEPRVA).
//  2. Builds a merged base-relocation table (existing host blocks +
//     one new DIR64 entry pointing at the slot) and places it in a
//     fresh `.mldreloc` section appended after the stub.
//  3. Re-points the BASERELOC DataDirectory at the new section.
//
// Under ASLR the loader rebases the slot via the new DIR64 entry,
// so the absolute VA we baked at pack time stays consistent with
// the actual mapped image base at runtime.
//
// `stubBytes` MUST be the output of [github.com/oioio-space/maldev/pe/packer/stubgen/stage1.EmitDLLStub]
// AFTER [stage1.PatchDLLStubDisplacements] has rewritten the R15-relative
// disp sentinels — but BEFORE [stage1.PatchDllMainSlot] runs.
// InjectStubDLL calls into the slot patcher itself once it knows the
// imageBase of the host (read from the input's Optional Header).
func InjectStubDLL(input, encryptedText, stubBytes []byte, plan Plan) ([]byte, error) {
	if plan.Format != FormatPE {
		return nil, ErrPlanFormatMismatch
	}
	if !plan.IsDLL {
		return nil, fmt.Errorf("transform: InjectStubDLL requires plan.IsDLL=true (route EXE inputs through InjectStubPE)")
	}
	if uint32(len(stubBytes)) > plan.StubMaxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrStubTooLarge, len(stubBytes), plan.StubMaxSize)
	}
	if uint32(len(encryptedText)) != plan.TextSize {
		return nil, fmt.Errorf("transform: encryptedText len %d != plan.TextSize %d", len(encryptedText), plan.TextSize)
	}
	if uint32(len(stubBytes)) < DLLStubSlotByteOffsetFromEnd {
		return nil, fmt.Errorf("transform: stubBytes (%d B) too short to carry the DllMain slot", len(stubBytes))
	}

	// === Phase 1: pre-fill the DllMain slot with imageBase + OEPRVA ===
	//
	// Read imageBase from the input's Optional Header. PE32+ stores
	// ImageBase at optOff+24 (uint64), per PE/COFF spec §3.4.2.
	imageBase, err := readImageBase(input)
	if err != nil {
		return nil, fmt.Errorf("transform: read ImageBase: %w", err)
	}
	absDllMainVA := imageBase + uint64(plan.OEPRVA)
	// Mutate stubBytes in-place — the caller owns the buffer and
	// won't reuse it past this point (mirrors how stage1.PatchTextDisplacement
	// mutates stubBytes in InjectStubPE's pipeline).
	slotOff, err := PatchDLLStubSlot(stubBytes, absDllMainVA)
	if err != nil {
		return nil, fmt.Errorf("transform: patch DllMain slot: %w", err)
	}

	// === Phase 2: clone InjectStubPE's body (write text, append stub section) ===
	//
	// We don't call InjectStubPE directly because:
	//   - it calls selfTestPE which would refuse a DLL (loader
	//     rejects the modified output until reloc patching, phase 3,
	//     is also done);
	//   - we need the output buffer AFTER appending the stub but
	//     BEFORE patching the reloc directory, to know the stub
	//     section's file offset for the reloc-section append.
	peOff := binary.LittleEndian.Uint32(input[PEELfanewOffset:])
	coffOff := peOff + PESignatureSize
	optOff := coffOff + PECOFFHdrSize
	fileAlign := binary.LittleEndian.Uint32(input[optOff+OptFileAlignOffset:])
	sectionAlign := binary.LittleEndian.Uint32(input[optOff+OptSectionAlignOffset:])
	stubFileSize := AlignUpU32(plan.StubMaxSize, fileAlign)

	// We'll grow the output beyond plan.StubFileOff+stubFileSize to
	// accommodate the appended `.mldreloc` section. Reserve space
	// for one IMAGE_BASE_RELOCATION block large enough to hold the
	// entire merged reloc table.
	slotRVA := plan.StubRVA + uint32(slotOff)
	mergedReloc, err := buildMergedRelocTable(input, slotRVA)
	if err != nil {
		return nil, fmt.Errorf("transform: build merged reloc table: %w", err)
	}

	relocFileOff := AlignUpU32(plan.StubFileOff+stubFileSize, fileAlign)
	relocRVA := AlignUpU32(plan.StubRVA+plan.StubMaxSize, sectionAlign)
	relocFileSize := AlignUpU32(uint32(len(mergedReloc)), fileAlign)
	totalSize := relocFileOff + relocFileSize

	out := make([]byte, totalSize)
	copy(out, input)
	copy(out[plan.TextFileOff:plan.TextFileOff+plan.TextSize], encryptedText)

	// Mark .text RWX so the stub can decrypt in place.
	textChars := binary.LittleEndian.Uint32(out[plan.TextHdrOff+SecCharacteristicsOffset:])
	textChars |= scnMemWrite
	binary.LittleEndian.PutUint32(out[plan.TextHdrOff+SecCharacteristicsOffset:], textChars)

	// === Phase 3: append the stub + reloc section headers ===
	numSections := binary.LittleEndian.Uint16(out[coffOff+COFFNumSectionsOffset:])
	sizeOfOptHdr := binary.LittleEndian.Uint16(out[coffOff+COFFSizeOfOptHdrOffset:])
	secTableOff := optOff + uint32(sizeOfOptHdr)
	newStubHdr := secTableOff + uint32(numSections)*PESectionHdrSize
	if int(newStubHdr)+2*PESectionHdrSize > int(plan.TextFileOff) {
		return nil, ErrSectionTableFull
	}
	stubName := plan.StubSectionName
	if stubName == ([8]byte{}) {
		stubName = defaultStubSectionName
	}
	writeSectionHeader(out[newStubHdr:], stubName, plan.StubMaxSize, plan.StubRVA, stubFileSize, plan.StubFileOff, scnCntCode|scnMemExec|ScnMemRead)

	// === Phase 4: append the reloc section header ===
	newRelocHdr := newStubHdr + PESectionHdrSize
	writeSectionHeader(out[newRelocHdr:], defaultRelocSectionName, uint32(len(mergedReloc)), relocRVA, relocFileSize, relocFileOff, ScnCntInitData|ScnMemRead)

	// Bump NumberOfSections by 2 (stub + reloc).
	binary.LittleEndian.PutUint16(out[coffOff+COFFNumSectionsOffset:], numSections+2)

	// === Phase 5: update DataDirectory[BASERELOC] + SizeOfImage + entry point ===
	binary.LittleEndian.PutUint32(out[optOff+OptDataDirsStart+dirBaseReloc*OptDataDirEntrySize:], relocRVA)
	binary.LittleEndian.PutUint32(out[optOff+OptDataDirsStart+dirBaseReloc*OptDataDirEntrySize+4:], uint32(len(mergedReloc)))

	// SizeOfImage must cover both new sections.
	newSizeOfImage := AlignUpU32(relocRVA+uint32(len(mergedReloc)), sectionAlign)
	binary.LittleEndian.PutUint32(out[optOff+OptSizeOfImageOffset:], newSizeOfImage)

	// Rewrite entry point — the loader calls our stub, which tail-calls
	// the original DllMain via the slot we just patched.
	binary.LittleEndian.PutUint32(out[optOff+OptAddrEntryOffset:], plan.StubRVA)

	// === Phase 6: write stub bytes + reloc bytes into reserved file regions ===
	copy(out[plan.StubFileOff:plan.StubFileOff+uint32(len(stubBytes))], stubBytes)
	copy(out[relocFileOff:relocFileOff+uint32(len(mergedReloc))], mergedReloc)

	return out, nil
}

// readImageBase returns the PE32+ Optional Header's ImageBase
// field. PE32+ stores it as a uint64 at optOff+24 per PE/COFF §3.4.2.
func readImageBase(input []byte) (uint64, error) {
	l, err := parsePELayout(input)
	if err != nil {
		return 0, err
	}
	if int(l.optOff)+32 > len(input) {
		return 0, fmt.Errorf("transform: optional header too short for ImageBase")
	}
	return binary.LittleEndian.Uint64(input[l.optOff+24 : l.optOff+32]), nil
}


// buildMergedRelocTable produces a fresh base-relocation table
// that is the host's existing relocs (block-by-block, copied
// verbatim) PLUS one new IMAGE_BASE_RELOCATION block covering the
// DllMain slot RVA with a single DIR64 entry.
//
// The new block is appended at the end so any callers walking the
// table block-by-block see the host's relocs in their original
// order followed by ours.
func buildMergedRelocTable(input []byte, slotRVA uint32) ([]byte, error) {
	l, err := parsePELayout(input)
	if err != nil {
		return nil, err
	}
	dirOff := l.optOff + OptDataDirsStart + dirBaseReloc*OptDataDirEntrySize
	if int(dirOff)+OptDataDirEntrySize > len(input) {
		return nil, fmt.Errorf("transform: input too short for BASERELOC DataDirectory")
	}
	dirRVA := binary.LittleEndian.Uint32(input[dirOff:])
	dirSize := binary.LittleEndian.Uint32(input[dirOff+4:])
	if dirRVA == 0 || dirSize == 0 {
		// DLL with no BASERELOC entry — loader will refuse to relocate
		// us under ASLR. Reject; the operator should pack a DLL that
		// has its standard reloc table.
		return nil, ErrNoExistingRelocDir
	}
	fileOff, err := rvaToFileOff(input, l, dirRVA)
	if err != nil {
		return nil, fmt.Errorf("transform: locate existing reloc table: %w", err)
	}
	if int(fileOff)+int(dirSize) > len(input) {
		return nil, fmt.Errorf("transform: existing reloc table extends past input EOF")
	}

	// New IMAGE_BASE_RELOCATION block: 8B header + 1 entry (2B) +
	// 1 Absolute padding entry (2B) = 12 B. Each entry is
	// (type << 12) | (rva & 0xFFF). BlockSize must be 4-byte aligned.
	const blockSize = 12
	pageRVA := slotRVA &^ 0xFFF
	entry := (RelTypeDir64 << 12) | uint16(slotRVA&0x0FFF)

	merged := make([]byte, 0, int(dirSize)+blockSize)
	merged = append(merged, input[fileOff:fileOff+dirSize]...)
	merged = binary.LittleEndian.AppendUint32(merged, pageRVA)
	merged = binary.LittleEndian.AppendUint32(merged, blockSize)
	merged = binary.LittleEndian.AppendUint16(merged, entry)
	merged = binary.LittleEndian.AppendUint16(merged, 0) // RelTypeAbsolute padding
	return merged, nil
}

// writeSectionHeader fills 40 bytes at hdr[:] with a PE section
// header carrying the given name + sizes + characteristics. Helper
// used by InjectStubDLL to keep the two section appends symmetric.
func writeSectionHeader(hdr []byte, name [8]byte, virtualSize, virtualAddress, rawSize, rawOff uint32, characteristics uint32) {
	copy(hdr[0:8], name[:])
	binary.LittleEndian.PutUint32(hdr[SecVirtualSizeOffset:], virtualSize)
	binary.LittleEndian.PutUint32(hdr[SecVirtualAddressOffset:], virtualAddress)
	binary.LittleEndian.PutUint32(hdr[SecSizeOfRawDataOffset:], rawSize)
	binary.LittleEndian.PutUint32(hdr[SecPointerToRawDataOffset:], rawOff)
	binary.LittleEndian.PutUint32(hdr[SecCharacteristicsOffset:], characteristics)
}

