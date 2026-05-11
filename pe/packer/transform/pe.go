package transform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// PE field offsets (from Microsoft PE/COFF Specification Rev 12.0).
const (
	peELfanewOffset  = 0x3C
	peSigSize        = 4
	peCOFFHdrSize    = 20
	peSectionHdrSize = 40

	// COFF File Header field offsets (relative to COFF start)
	coffNumSectionsOffset       = 0x02
	coffSizeOfOptionalHdrOffset = 0x10

	// PE32+ Optional Header field offsets (relative to opt start)
	optAddrEntryOffset    = 0x10
	optSectionAlignOffset = 0x20
	optFileAlignOffset    = 0x24
	optSizeOfImageOffset  = 0x38
	optDataDirsStart      = 0x70
	optDataDirEntrySize   = 8
	tlsDataDirIndex       = 9

	// Section Header field offsets
	secVirtualSizeOffset      = 0x08
	secVirtualAddressOffset   = 0x0C
	secSizeOfRawDataOffset    = 0x10
	secPointerToRawDataOffset = 0x14
	secCharacteristicsOffset  = 0x24

	// Section Characteristics flags (PE/COFF)
	scnCntCode  = 0x00000020
	scnMemExec  = 0x20000000
	scnMemRead  = 0x40000000
	scnMemWrite = 0x80000000
)

// planExpect selects which COFF Characteristics admission rule
// planPECore applies — see [PlanPE] / [PlanDLL].
type planExpect uint8

const (
	expectEXE planExpect = iota // input must NOT carry IMAGE_FILE_DLL
	expectDLL                   // input MUST carry IMAGE_FILE_DLL
)

// PlanPE inspects an input PE32+ EXE and computes the transform layout.
// Doesn't modify input. Returns ErrTLSCallbacks if the input has
// TLS callbacks, ErrOEPOutsideText if the entry point isn't within
// .text, ErrNoTextSection if .text is missing, ErrIsDLL when the
// input carries IMAGE_FILE_DLL (route those through [PlanDLL] instead).
func PlanPE(input []byte, stubMaxSize uint32) (Plan, error) {
	return planPECore(input, stubMaxSize, expectEXE)
}

// PlanDLL is the DLL counterpart of [PlanPE]: it requires the
// input to carry the IMAGE_FILE_DLL bit and returns a [Plan]
// with [Plan.IsDLL] set so the stub emitter selects the DllMain
// prologue/epilogue layout (see docs/refactor-2026-doc/packer-dll-format-plan.md).
//
// Sentinels match [PlanPE], with one inversion: PlanDLL returns
// [ErrIsEXE] when handed an EXE (mirror of PlanPE's [ErrIsDLL]
// rejection).
func PlanDLL(input []byte, stubMaxSize uint32) (Plan, error) {
	return planPECore(input, stubMaxSize, expectDLL)
}

// PlanConvertedDLL accepts a PE32+ EXE and returns a [Plan] flagged
// for the EXE→DLL conversion path ([Plan.IsConvertedDLL] set;
// [Plan.IsDLL] clear). Same admission rules + sentinels as [PlanPE]
// (rejects DLL inputs with [ErrIsDLL]); the actual format flip
// happens at injection time.
//
// See docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
func PlanConvertedDLL(input []byte, stubMaxSize uint32) (Plan, error) {
	plan, err := planPECore(input, stubMaxSize, expectEXE)
	if err != nil {
		return Plan{}, err
	}
	plan.IsConvertedDLL = true
	return plan, nil
}

// planPECore is the shared body of PlanPE and PlanDLL.
func planPECore(input []byte, stubMaxSize uint32, expect planExpect) (Plan, error) {
	if DetectFormat(input) != FormatPE {
		return Plan{}, ErrUnsupportedInputFormat
	}
	if len(input) < peELfanewOffset+4 {
		return Plan{}, fmt.Errorf("%w: input too short for DOS header", ErrUnsupportedInputFormat)
	}

	peOff := binary.LittleEndian.Uint32(input[peELfanewOffset : peELfanewOffset+4])
	if int(peOff)+peSigSize+peCOFFHdrSize > len(input) {
		return Plan{}, fmt.Errorf("%w: e_lfanew past end of input", ErrUnsupportedInputFormat)
	}
	if binary.LittleEndian.Uint32(input[peOff:peOff+4]) != 0x00004550 {
		return Plan{}, fmt.Errorf("%w: missing PE signature", ErrUnsupportedInputFormat)
	}

	coffOff := peOff + peSigSize
	// IMAGE_FILE_DLL admission. EXE path refuses DLLs because the
	// stub design assumes EXE entry-point semantics (arg-less call
	// from kernel + ExitProcess at end). DLL path refuses EXEs
	// because the DllMain stub layout would overwrite a valid EXE
	// entry point with a trampoline reading bogus rcx/edx/r8 args.
	hasDLLBit := binary.LittleEndian.Uint16(input[coffOff+0x12:coffOff+0x14])&ImageFileDLL != 0
	switch {
	case hasDLLBit && expect == expectEXE:
		return Plan{}, ErrIsDLL
	case !hasDLLBit && expect == expectDLL:
		return Plan{}, ErrIsEXE
	}
	numSections := binary.LittleEndian.Uint16(input[coffOff+coffNumSectionsOffset : coffOff+coffNumSectionsOffset+2])
	sizeOfOptHdr := binary.LittleEndian.Uint16(input[coffOff+coffSizeOfOptionalHdrOffset : coffOff+coffSizeOfOptionalHdrOffset+2])

	optOff := coffOff + peCOFFHdrSize
	if int(optOff)+int(sizeOfOptHdr) > len(input) {
		return Plan{}, fmt.Errorf("%w: optional header past end of input", ErrUnsupportedInputFormat)
	}

	oepRVA := binary.LittleEndian.Uint32(input[optOff+optAddrEntryOffset : optOff+optAddrEntryOffset+4])
	sectionAlign := binary.LittleEndian.Uint32(input[optOff+optSectionAlignOffset : optOff+optSectionAlignOffset+4])
	fileAlign := binary.LittleEndian.Uint32(input[optOff+optFileAlignOffset : optOff+optFileAlignOffset+4])

	// Reject TLS callbacks — they run before OEP and would touch encrypted bytes.
	tlsDirOff := optOff + optDataDirsStart + tlsDataDirIndex*optDataDirEntrySize
	if int(tlsDirOff)+8 <= len(input) {
		tlsRVA := binary.LittleEndian.Uint32(input[tlsDirOff : tlsDirOff+4])
		if tlsRVA != 0 {
			return Plan{}, ErrTLSCallbacks
		}
	}

	// Walk section table — find .text + last section's end.
	secTableOff := optOff + uint32(sizeOfOptHdr)
	if int(secTableOff)+int(numSections)*peSectionHdrSize > len(input) {
		return Plan{}, fmt.Errorf("%w: section table past end of input", ErrUnsupportedInputFormat)
	}

	var (
		textRVA       uint32
		textFileOff   uint32
		textSize      uint32
		textHdrOff    uint32
		textFound     bool
		lastSecEndRVA uint32
		lastSecEndOff uint32
	)
	textPrefix := []byte(".text")
	for i := uint16(0); i < numSections; i++ {
		hdrOff := secTableOff + uint32(i)*peSectionHdrSize
		va := binary.LittleEndian.Uint32(input[hdrOff+secVirtualAddressOffset : hdrOff+secVirtualAddressOffset+4])
		vs := binary.LittleEndian.Uint32(input[hdrOff+secVirtualSizeOffset : hdrOff+secVirtualSizeOffset+4])
		rs := binary.LittleEndian.Uint32(input[hdrOff+secSizeOfRawDataOffset : hdrOff+secSizeOfRawDataOffset+4])
		pf := binary.LittleEndian.Uint32(input[hdrOff+secPointerToRawDataOffset : hdrOff+secPointerToRawDataOffset+4])

		// bytes.HasPrefix avoids the per-iteration string() heap
		// alloc that the previous string(input[...]) did.
		if !textFound && bytes.HasPrefix(input[hdrOff:hdrOff+8], textPrefix) {
			textRVA = va
			textFileOff = pf
			textSize = vs
			textHdrOff = hdrOff
			textFound = true
		}
		end := alignUpU32(va+vs, sectionAlign)
		if end > lastSecEndRVA {
			lastSecEndRVA = end
		}
		fileEnd := pf + rs
		if fileEnd > lastSecEndOff {
			lastSecEndOff = fileEnd
		}
	}

	if !textFound {
		return Plan{}, ErrNoTextSection
	}
	if oepRVA < textRVA || oepRVA >= textRVA+textSize {
		return Plan{}, fmt.Errorf("%w: OEP %#x not in .text [%#x, %#x)",
			ErrOEPOutsideText, oepRVA, textRVA, textRVA+textSize)
	}

	stubRVA := alignUpU32(lastSecEndRVA, sectionAlign)
	stubFileOff := alignUpU32(lastSecEndOff, fileAlign)

	return Plan{
		Format:      FormatPE,
		TextRVA:     textRVA,
		TextFileOff: textFileOff,
		TextSize:    textSize,
		TextHdrOff:  textHdrOff,
		OEPRVA:      oepRVA,
		StubRVA:     stubRVA,
		StubFileOff: stubFileOff,
		StubMaxSize: stubMaxSize,
		IsDLL:       expect == expectDLL,
	}, nil
}

// InjectStubPE applies the planned mutations: writes encryptedText
// into .text's file slot, marks .text RWX, appends a new section
// header for the stub, writes stub bytes, rewrites the entry point.
func InjectStubPE(input, encryptedText, stubBytes []byte, plan Plan) ([]byte, error) {
	if plan.Format != FormatPE {
		return nil, ErrPlanFormatMismatch
	}
	if uint32(len(stubBytes)) > plan.StubMaxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrStubTooLarge, len(stubBytes), plan.StubMaxSize)
	}
	if uint32(len(encryptedText)) != plan.TextSize {
		return nil, fmt.Errorf("transform: encryptedText len %d != plan.TextSize %d", len(encryptedText), plan.TextSize)
	}

	// Extend to accommodate the stub's file slot past the existing image end.
	peOff := binary.LittleEndian.Uint32(input[peELfanewOffset : peELfanewOffset+4])
	coffOff := peOff + peSigSize
	optOff := coffOff + peCOFFHdrSize
	fileAlign := binary.LittleEndian.Uint32(input[optOff+optFileAlignOffset : optOff+optFileAlignOffset+4])
	stubFileSize := alignUpU32(plan.StubMaxSize, fileAlign)
	totalSize := plan.StubFileOff + stubFileSize

	out := make([]byte, totalSize)
	copy(out, input)

	// Overwrite .text raw bytes with the caller-encrypted payload.
	copy(out[plan.TextFileOff:plan.TextFileOff+plan.TextSize], encryptedText)

	// Set MEM_WRITE on .text so the stub can decrypt in place at runtime.
	sizeOfOptHdr := binary.LittleEndian.Uint16(out[coffOff+coffSizeOfOptionalHdrOffset : coffOff+coffSizeOfOptionalHdrOffset+2])
	secTableOff := optOff + uint32(sizeOfOptHdr)
	numSections := binary.LittleEndian.Uint16(out[coffOff+coffNumSectionsOffset : coffOff+coffNumSectionsOffset+2])

	// Plan.TextHdrOff is set by PlanPE so InjectStubPE skips the
	// re-walk of the section table and the per-iteration string()
	// allocation that used to back the comparison.
	textHdrOff := plan.TextHdrOff
	if textHdrOff == 0 {
		return nil, ErrNoTextSection
	}
	textChars := binary.LittleEndian.Uint32(out[textHdrOff+secCharacteristicsOffset : textHdrOff+secCharacteristicsOffset+4])
	textChars |= scnMemWrite
	binary.LittleEndian.PutUint32(out[textHdrOff+secCharacteristicsOffset:textHdrOff+secCharacteristicsOffset+4], textChars)

	// When compression is active TextMemSize > TextSize: the on-disk payload is the
	// compressed bytes (filesz = TextSize) but the section needs more virtual memory
	// so the in-place inflate has room to expand. VirtualSize controls the mapped
	// window; SizeOfRawData (TextSize) controls how many bytes the kernel reads from
	// disk. The difference is mapped as zeroes by the kernel — exactly the workspace
	// the LZ4 inflate decoder needs.
	if plan.TextMemSize > plan.TextSize {
		binary.LittleEndian.PutUint32(
			out[textHdrOff+secVirtualSizeOffset:textHdrOff+secVirtualSizeOffset+4],
			plan.TextMemSize,
		)
	}

	// Append a new stub section header immediately after the existing table.
	// make([]byte, totalSize) guarantees zero bytes in the new-header slot.
	newHdrOff := secTableOff + uint32(numSections)*peSectionHdrSize
	if int(newHdrOff)+peSectionHdrSize > int(plan.TextFileOff) {
		return nil, ErrSectionTableFull
	}
	// Section name: caller-supplied via plan.StubSectionName, or
	// the canonical ".mldv\x00\x00\x00" when left zero. Phase 2-A
	// (docs/refactor-2026-doc/packer-design.md) lets operators
	// override per-pack to defeat YARA on the literal name.
	if plan.StubSectionName == ([8]byte{}) {
		copy(out[newHdrOff:newHdrOff+8], []byte(".mldv\x00\x00\x00"))
	} else {
		copy(out[newHdrOff:newHdrOff+8], plan.StubSectionName[:])
	}
	// VirtualSize includes the StubScratchSize trailing region — when set,
	// the loader maps that gap as zero (BSS). C3 compression uses it as the
	// scratch buffer for non-in-place LZ4 inflate, sidestepping the
	// constraint that the .text section can't grow past the next mapped
	// section.
	binary.LittleEndian.PutUint32(out[newHdrOff+secVirtualSizeOffset:newHdrOff+secVirtualSizeOffset+4], plan.StubMaxSize+plan.StubScratchSize)
	binary.LittleEndian.PutUint32(out[newHdrOff+secVirtualAddressOffset:newHdrOff+secVirtualAddressOffset+4], plan.StubRVA)
	binary.LittleEndian.PutUint32(out[newHdrOff+secSizeOfRawDataOffset:newHdrOff+secSizeOfRawDataOffset+4], stubFileSize)
	binary.LittleEndian.PutUint32(out[newHdrOff+secPointerToRawDataOffset:newHdrOff+secPointerToRawDataOffset+4], plan.StubFileOff)
	binary.LittleEndian.PutUint32(out[newHdrOff+secCharacteristicsOffset:newHdrOff+secCharacteristicsOffset+4],
		scnCntCode|scnMemExec|scnMemRead)

	binary.LittleEndian.PutUint16(out[coffOff+coffNumSectionsOffset:coffOff+coffNumSectionsOffset+2], numSections+1)

	// SizeOfImage must cover the new section's virtual span; the loader
	// rejects the image at load time if this is too small.
	sectionAlign := binary.LittleEndian.Uint32(out[optOff+optSectionAlignOffset : optOff+optSectionAlignOffset+4])
	newSizeOfImage := alignUpU32(plan.StubRVA+plan.StubMaxSize, sectionAlign)
	binary.LittleEndian.PutUint32(out[optOff+optSizeOfImageOffset:optOff+optSizeOfImageOffset+4], newSizeOfImage)

	binary.LittleEndian.PutUint32(out[optOff+optAddrEntryOffset:optOff+optAddrEntryOffset+4], plan.StubRVA)

	copy(out[plan.StubFileOff:plan.StubFileOff+uint32(len(stubBytes))], stubBytes)

	if err := selfTestPE(out, plan); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptOutput, err)
	}
	return out, nil
}

func selfTestPE(out []byte, plan Plan) error {
	// Manual byte check — cheaper than importing debug/pe and avoids
	// dragging the test-only stdlib parser into production code paths.
	peOff := binary.LittleEndian.Uint32(out[peELfanewOffset : peELfanewOffset+4])
	coffOff := peOff + peSigSize
	optOff := coffOff + peCOFFHdrSize
	gotEntry := binary.LittleEndian.Uint32(out[optOff+optAddrEntryOffset : optOff+optAddrEntryOffset+4])
	if gotEntry != plan.StubRVA {
		return errors.New("AddressOfEntryPoint not updated to StubRVA")
	}
	gotNum := binary.LittleEndian.Uint16(out[coffOff+coffNumSectionsOffset : coffOff+coffNumSectionsOffset+2])
	// We bumped by 1; the original input had at least 1 section.
	if gotNum < 2 {
		return errors.New("NumberOfSections not bumped after stub append")
	}
	return nil
}

// AlignUpU32 rounds v up to the nearest multiple of align.
// Exported so sibling packages in pe/packer/ can reuse the same
// alignment math without re-deriving it. Returns v unchanged when
// align is 0 (defensive — alignment of 0 is malformed PE/ELF).
func AlignUpU32(v, align uint32) uint32 {
	if align == 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// alignUpU32 keeps the in-package call sites concise.
func alignUpU32(v, align uint32) uint32 { return AlignUpU32(v, align) }
