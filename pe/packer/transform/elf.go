package transform

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
)

// ELF64 field offsets (System V ABI AMD64 Rev 1.0).
const (
	elfEhdrSize = 64
	elfPhdrSize = 56
	elfPageSize = 0x1000

	// Ehdr offsets
	elfEntryOffset     = 0x18
	elfPhoffOffset     = 0x20
	elfPhentsizeOffset = 0x36
	elfPhnumOffset     = 0x38

	// Phdr offsets (type is at 0x00, read as input[off:off+4] directly)
	elfPhdrFlagsOffset  = 0x04
	elfPhdrOffsetOffset = 0x08
	elfPhdrVAddrOffset  = 0x10
	elfPhdrPAddrOffset  = 0x18
	elfPhdrFileSzOffset = 0x20
	elfPhdrMemSzOffset  = 0x28
	elfPhdrAlignOffset  = 0x30

	elfPF_X    = 1
	elfPF_W    = 2
	elfPF_R    = 4
	elfPT_LOAD = 1
)

// PlanELF inspects an input ELF64 and computes the transform layout.
//
// Go static-PIE binaries pack the ELF header into the first executable
// PT_LOAD (file offset 0). Encrypting the whole segment would destroy the
// header, so we locate the .text SECTION via the section-header table
// (using debug/elf) and use its tighter bounds for TextRVA/TextFileOff/
// TextSize. The encrypted region covers only actual code; the ELF header,
// program-header table, and non-text data remain pristine for the kernel.
//
// We still walk the PT_LOAD table to compute StubRVA/StubFileOff, and to
// confirm .text is inside an executable segment.
//
// Returns ErrNoTextSection when:
//   - no .text section exists (stripped binary), or
//   - .text is not inside an executable PT_LOAD.
//
// Returns ErrOEPOutsideText if e_entry is not within the .text section.
func PlanELF(input []byte, stubMaxSize uint32) (Plan, error) {
	if DetectFormat(input) != FormatELF {
		return Plan{}, ErrUnsupportedInputFormat
	}
	if len(input) < elfEhdrSize {
		return Plan{}, fmt.Errorf("%w: input shorter than Ehdr", ErrUnsupportedInputFormat)
	}
	// Require ELFCLASS64 + ELFDATA2LSB — only layout we know.
	if input[4] != 2 || input[5] != 1 {
		return Plan{}, fmt.Errorf("%w: not ELFCLASS64+LE", ErrUnsupportedInputFormat)
	}

	entry := binary.LittleEndian.Uint64(input[elfEntryOffset : elfEntryOffset+8])
	phoff := binary.LittleEndian.Uint64(input[elfPhoffOffset : elfPhoffOffset+8])
	phnum := binary.LittleEndian.Uint16(input[elfPhnumOffset : elfPhnumOffset+2])
	phentsize := binary.LittleEndian.Uint16(input[elfPhentsizeOffset : elfPhentsizeOffset+2])
	if phentsize != elfPhdrSize {
		return Plan{}, fmt.Errorf("%w: phentsize %d != %d", ErrUnsupportedInputFormat, phentsize, elfPhdrSize)
	}

	// Walk PT_LOAD headers to find the executable segment bounds and
	// compute where the new stub PT_LOAD can be appended.
	var (
		textSegVAddrStart uint64
		textSegVAddrEnd   uint64
		textSegFound      bool
		lastEnd           uint64 // highest virtual end across all PT_LOADs
		lastFEnd          uint64 // highest file end across all PT_LOADs
	)
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*uint64(phentsize)
		if int(off)+int(phentsize) > len(input) {
			return Plan{}, fmt.Errorf("%w: phdr past end of input", ErrUnsupportedInputFormat)
		}
		ptype := binary.LittleEndian.Uint32(input[off : off+4])
		flags := binary.LittleEndian.Uint32(input[off+elfPhdrFlagsOffset : off+elfPhdrFlagsOffset+4])
		va := binary.LittleEndian.Uint64(input[off+elfPhdrVAddrOffset : off+elfPhdrVAddrOffset+8])
		fs := binary.LittleEndian.Uint64(input[off+elfPhdrFileSzOffset : off+elfPhdrFileSzOffset+8])
		ms := binary.LittleEndian.Uint64(input[off+elfPhdrMemSzOffset : off+elfPhdrMemSzOffset+8])
		o := binary.LittleEndian.Uint64(input[off+elfPhdrOffsetOffset : off+elfPhdrOffsetOffset+8])

		if ptype == elfPT_LOAD && !textSegFound && (flags&elfPF_X) != 0 {
			textSegVAddrStart = va
			textSegVAddrEnd = va + fs
			textSegFound = true
		}
		if ptype == elfPT_LOAD {
			end := alignUpU64(va+ms, elfPageSize)
			if end > lastEnd {
				lastEnd = end
			}
			fEnd := o + fs
			if fEnd > lastFEnd {
				lastFEnd = fEnd
			}
		}
	}

	if !textSegFound {
		return Plan{}, ErrNoTextSection
	}

	// Use debug/elf to locate the .text section precisely. Go static-PIE
	// binaries embed the ELF header inside the first executable PT_LOAD, so
	// using the segment bounds directly would encrypt the header and corrupt
	// e_phoff, causing the kernel to reject the output and InjectStubELF to
	// read ciphertext as a file offset.
	ef, err := elf.NewFile(bytes.NewReader(input))
	if err != nil {
		return Plan{}, fmt.Errorf("%w: debug/elf rejected input: %v", ErrUnsupportedInputFormat, err)
	}
	defer ef.Close()

	textSection := ef.Section(".text")
	if textSection == nil {
		return Plan{}, fmt.Errorf("%w: no .text section (stripped binary?)", ErrNoTextSection)
	}

	textVAddr := textSection.Addr
	textFileOff := textSection.Offset
	textSize := textSection.FileSize

	// Cross-check: .text must reside within the executable PT_LOAD we found.
	// This guards against stripped binaries where .text might be absent or
	// misplaced relative to the phdr layout.
	if textVAddr < textSegVAddrStart || textVAddr+textSize > textSegVAddrEnd {
		return Plan{}, fmt.Errorf("%w: .text section [%#x, %#x) not inside executable PT_LOAD [%#x, %#x)",
			ErrNoTextSection, textVAddr, textVAddr+textSize, textSegVAddrStart, textSegVAddrEnd)
	}

	if entry < textVAddr || entry >= textVAddr+textSize {
		return Plan{}, fmt.Errorf("%w: entry %#x not in .text [%#x, %#x)",
			ErrOEPOutsideText, entry, textVAddr, textVAddr+textSize)
	}

	return Plan{
		Format:      FormatELF,
		TextRVA:     uint32(textVAddr),
		TextFileOff: uint32(textFileOff),
		TextSize:    uint32(textSize),
		OEPRVA:      uint32(entry),
		StubRVA:     uint32(alignUpU64(lastEnd, elfPageSize)),
		StubFileOff: uint32(alignUpU64(lastFEnd, elfPageSize)),
		StubMaxSize: stubMaxSize,
	}, nil
}

// InjectStubELF applies the planned mutations: writes encryptedText
// into the text section's file slot, ORs PF_W into the text segment's
// flags (RWX), appends a new PT_LOAD entry (R+E) with the stub bytes,
// bumps e_phnum, rewrites e_entry. Pre-return self-test verifies e_entry
// and e_phnum.
//
// All reads of phdr metadata use the original input buffer. Mutations
// are written to out. This strict separation avoids reading ciphertext
// as a file offset when the encrypted region overlaps the phdr table.
func InjectStubELF(input, encryptedText, stubBytes []byte, plan Plan) ([]byte, error) {
	if plan.Format != FormatELF {
		return nil, ErrPlanFormatMismatch
	}
	if uint32(len(stubBytes)) > plan.StubMaxSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrStubTooLarge, len(stubBytes), plan.StubMaxSize)
	}
	if uint32(len(encryptedText)) != plan.TextSize {
		return nil, fmt.Errorf("transform: encryptedText len %d != plan.TextSize %d", len(encryptedText), plan.TextSize)
	}

	// Read all phdr metadata from input BEFORE any mutation, to avoid
	// interpreting ciphertext as offsets if the encrypted region touches
	// the header area.
	phoff := binary.LittleEndian.Uint64(input[elfPhoffOffset : elfPhoffOffset+8])
	phnum := binary.LittleEndian.Uint16(input[elfPhnumOffset : elfPhnumOffset+2])

	textPhdrOff := uint64(0)
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*elfPhdrSize
		flags := binary.LittleEndian.Uint32(input[off+elfPhdrFlagsOffset : off+elfPhdrFlagsOffset+4])
		va := binary.LittleEndian.Uint64(input[off+elfPhdrVAddrOffset : off+elfPhdrVAddrOffset+8])
		// Match the executable PT_LOAD that contains .text by vaddr.
		// plan.TextRVA is the .text section's vaddr, which lies inside
		// the executable segment; find that segment by checking the
		// segment's vaddr range.
		fs := binary.LittleEndian.Uint64(input[off+elfPhdrFileSzOffset : off+elfPhdrFileSzOffset+8])
		if (flags&elfPF_X) != 0 && va <= uint64(plan.TextRVA) && uint64(plan.TextRVA) < va+fs {
			textPhdrOff = off
			break
		}
	}
	if textPhdrOff == 0 {
		return nil, ErrNoTextSection
	}

	stubPagedSize := alignUpU32(plan.StubMaxSize, elfPageSize)
	totalSize := plan.StubFileOff + stubPagedSize
	if int(totalSize) < len(input) {
		totalSize = uint32(len(input))
	}
	out := make([]byte, totalSize)
	copy(out, input)

	// 1. Replace text section bytes with the pre-encrypted payload.
	copy(out[plan.TextFileOff:plan.TextFileOff+plan.TextSize], encryptedText)

	// 2. Mark text PT_LOAD RWX: the stub will mprotect this range before
	//    decrypting; PF_W here ensures the kernel maps it writable in the
	//    first place for static-PIE cases.
	flags := binary.LittleEndian.Uint32(out[textPhdrOff+elfPhdrFlagsOffset : textPhdrOff+elfPhdrFlagsOffset+4])
	flags |= elfPF_W
	binary.LittleEndian.PutUint32(out[textPhdrOff+elfPhdrFlagsOffset:textPhdrOff+elfPhdrFlagsOffset+4], flags)

	// 3. Append new PT_LOAD R+E for stub after existing phdrs.
	// The input must have at least one phdr slot of slack between the
	// phdr table and the first PT_LOAD's file offset; real Go static-PIE
	// binaries always do. ErrSectionTableFull signals when they don't.
	newPhdrOff := phoff + uint64(phnum)*elfPhdrSize
	if int(newPhdrOff)+elfPhdrSize > int(plan.TextFileOff) {
		return nil, ErrSectionTableFull
	}
	binary.LittleEndian.PutUint32(out[newPhdrOff:newPhdrOff+4], elfPT_LOAD)
	binary.LittleEndian.PutUint32(out[newPhdrOff+elfPhdrFlagsOffset:newPhdrOff+elfPhdrFlagsOffset+4], elfPF_R|elfPF_X)
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrOffsetOffset:newPhdrOff+elfPhdrOffsetOffset+8], uint64(plan.StubFileOff))
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrVAddrOffset:newPhdrOff+elfPhdrVAddrOffset+8], uint64(plan.StubRVA))
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrPAddrOffset:newPhdrOff+elfPhdrPAddrOffset+8], uint64(plan.StubRVA)) // p_paddr = vaddr
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrFileSzOffset:newPhdrOff+elfPhdrFileSzOffset+8], uint64(plan.StubMaxSize))
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrMemSzOffset:newPhdrOff+elfPhdrMemSzOffset+8], uint64(plan.StubMaxSize))
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrAlignOffset:newPhdrOff+elfPhdrAlignOffset+8], elfPageSize)

	// 4. Bump e_phnum to include the new stub phdr.
	binary.LittleEndian.PutUint16(out[elfPhnumOffset:elfPhnumOffset+2], phnum+1)

	// 5. Rewrite e_entry to the stub's load address.
	binary.LittleEndian.PutUint64(out[elfEntryOffset:elfEntryOffset+8], uint64(plan.StubRVA))

	// 6. Write stub bytes into the reserved file slot.
	copy(out[plan.StubFileOff:plan.StubFileOff+uint32(len(stubBytes))], stubBytes)

	// 7. Pre-return self-test: confirms e_entry and e_phnum were written.
	if err := selfTestELF(out, plan); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptOutput, err)
	}
	return out, nil
}

func selfTestELF(out []byte, plan Plan) error {
	gotEntry := binary.LittleEndian.Uint64(out[elfEntryOffset : elfEntryOffset+8])
	if uint32(gotEntry) != plan.StubRVA {
		return errors.New("e_entry not updated to StubRVA")
	}
	gotPhnum := binary.LittleEndian.Uint16(out[elfPhnumOffset : elfPhnumOffset+2])
	if gotPhnum < 2 {
		return errors.New("e_phnum not bumped after stub append")
	}
	return nil
}

// AlignUpU64 rounds v up to the nearest multiple of align.
// Exported so sibling packages in pe/packer/ can reuse the same
// alignment math without re-deriving it. Returns v unchanged when
// align is 0 (defensive — alignment of 0 is malformed ELF).
func AlignUpU64(v, align uint64) uint64 {
	if align == 0 {
		return v
	}
	return (v + align - 1) &^ (align - 1)
}

// alignUpU64 keeps the in-package call sites concise.
func alignUpU64(v, align uint64) uint64 { return AlignUpU64(v, align) }
