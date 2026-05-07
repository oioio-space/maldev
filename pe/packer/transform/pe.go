package transform

import (
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

// PlanPE inspects an input PE32+ and computes the transform layout.
// Doesn't modify input. Returns ErrTLSCallbacks if the input has
// TLS callbacks, ErrOEPOutsideText if the entry point isn't within
// .text, ErrNoTextSection if .text is missing.
func PlanPE(input []byte, stubMaxSize uint32) (Plan, error) {
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
		textFound     bool
		lastSecEndRVA uint32
		lastSecEndOff uint32
	)
	for i := uint16(0); i < numSections; i++ {
		hdrOff := secTableOff + uint32(i)*peSectionHdrSize
		name := string(input[hdrOff : hdrOff+8])
		va := binary.LittleEndian.Uint32(input[hdrOff+secVirtualAddressOffset : hdrOff+secVirtualAddressOffset+4])
		vs := binary.LittleEndian.Uint32(input[hdrOff+secVirtualSizeOffset : hdrOff+secVirtualSizeOffset+4])
		rs := binary.LittleEndian.Uint32(input[hdrOff+secSizeOfRawDataOffset : hdrOff+secSizeOfRawDataOffset+4])
		pf := binary.LittleEndian.Uint32(input[hdrOff+secPointerToRawDataOffset : hdrOff+secPointerToRawDataOffset+4])

		if !textFound && name[:5] == ".text" {
			textRVA = va
			textFileOff = pf
			textSize = vs
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
		OEPRVA:      oepRVA,
		StubRVA:     stubRVA,
		StubFileOff: stubFileOff,
		StubMaxSize: stubMaxSize,
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

	textHdrOff := uint32(0)
	for i := uint16(0); i < numSections; i++ {
		hdrOff := secTableOff + uint32(i)*peSectionHdrSize
		name := string(out[hdrOff : hdrOff+8])
		if name[:5] == ".text" {
			textHdrOff = hdrOff
			break
		}
	}
	if textHdrOff == 0 {
		return nil, ErrNoTextSection
	}
	textChars := binary.LittleEndian.Uint32(out[textHdrOff+secCharacteristicsOffset : textHdrOff+secCharacteristicsOffset+4])
	textChars |= scnMemWrite
	binary.LittleEndian.PutUint32(out[textHdrOff+secCharacteristicsOffset:textHdrOff+secCharacteristicsOffset+4], textChars)

	// Append a new stub section header immediately after the existing table.
	// make([]byte, totalSize) guarantees zero bytes in the new-header slot.
	newHdrOff := secTableOff + uint32(numSections)*peSectionHdrSize
	if int(newHdrOff)+peSectionHdrSize > int(plan.TextFileOff) {
		return nil, ErrSectionTableFull
	}
	copy(out[newHdrOff:newHdrOff+8], []byte(".mldv\x00\x00\x00"))
	binary.LittleEndian.PutUint32(out[newHdrOff+secVirtualSizeOffset:newHdrOff+secVirtualSizeOffset+4], plan.StubMaxSize)
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
