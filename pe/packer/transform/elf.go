package transform

import (
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
	elfPhdrFileSzOffset = 0x20
	elfPhdrMemSzOffset  = 0x28

	elfPF_X    = 1
	elfPF_W    = 2
	elfPF_R    = 4
	elfPT_LOAD = 1
)

// PlanELF inspects an input ELF64 and computes the transform layout.
// Picks the FIRST PT_LOAD with PF_X as the "text" segment.
// Returns ErrOEPOutsideText if e_entry is not within that segment,
// ErrNoTextSection if no executable PT_LOAD exists.
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

	var (
		textOffset uint64
		textVAddr  uint64
		textSize   uint64
		textFound  bool
		lastEnd    uint64 // highest virtual end across all PT_LOADs
		lastFEnd   uint64 // highest file end across all PT_LOADs
	)
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*uint64(phentsize)
		if int(off)+int(phentsize) > len(input) {
			return Plan{}, fmt.Errorf("%w: phdr past end of input", ErrUnsupportedInputFormat)
		}
		ptype := binary.LittleEndian.Uint32(input[off : off+4])
		flags := binary.LittleEndian.Uint32(input[off+elfPhdrFlagsOffset : off+elfPhdrFlagsOffset+4])
		o := binary.LittleEndian.Uint64(input[off+elfPhdrOffsetOffset : off+elfPhdrOffsetOffset+8])
		va := binary.LittleEndian.Uint64(input[off+elfPhdrVAddrOffset : off+elfPhdrVAddrOffset+8])
		fs := binary.LittleEndian.Uint64(input[off+elfPhdrFileSzOffset : off+elfPhdrFileSzOffset+8])
		ms := binary.LittleEndian.Uint64(input[off+elfPhdrMemSzOffset : off+elfPhdrMemSzOffset+8])

		if ptype == elfPT_LOAD && !textFound && (flags&elfPF_X) != 0 {
			textOffset = o
			textVAddr = va
			textSize = fs
			textFound = true
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

	if !textFound {
		return Plan{}, ErrNoTextSection
	}
	if entry < textVAddr || entry >= textVAddr+textSize {
		return Plan{}, fmt.Errorf("%w: entry %#x not in text segment [%#x, %#x)",
			ErrOEPOutsideText, entry, textVAddr, textVAddr+textSize)
	}

	return Plan{
		Format:      FormatELF,
		TextRVA:     uint32(textVAddr),
		TextFileOff: uint32(textOffset),
		TextSize:    uint32(textSize),
		OEPRVA:      uint32(entry),
		StubRVA:     uint32(alignUpU64(lastEnd, elfPageSize)),
		StubFileOff: uint32(alignUpU64(lastFEnd, elfPageSize)),
		StubMaxSize: stubMaxSize,
	}, nil
}

// InjectStubELF applies the planned mutations: writes encryptedText
// into the text segment's file slot, ORs PF_W into its flags (RWX),
// appends a new PT_LOAD entry (R+E) with the stub bytes, bumps
// e_phnum, rewrites e_entry. Pre-return self-test verifies e_entry
// and e_phnum.
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

	stubPagedSize := alignUpU32(plan.StubMaxSize, elfPageSize)
	totalSize := plan.StubFileOff + stubPagedSize
	if int(totalSize) < len(input) {
		totalSize = uint32(len(input))
	}
	out := make([]byte, totalSize)
	copy(out, input)

	// 1. Replace text segment bytes with the pre-encrypted payload.
	copy(out[plan.TextFileOff:plan.TextFileOff+plan.TextSize], encryptedText)

	// 2. Mark text PT_LOAD RWX: the stub will VirtualProtect / mprotect
	//    this range before decrypting, but setting PF_W here ensures the
	//    kernel maps it writable in the first place for static-PIE cases.
	phoff := binary.LittleEndian.Uint64(out[elfPhoffOffset : elfPhoffOffset+8])
	phnum := binary.LittleEndian.Uint16(out[elfPhnumOffset : elfPhnumOffset+2])
	textPhdrOff := uint64(0)
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*elfPhdrSize
		flags := binary.LittleEndian.Uint32(out[off+elfPhdrFlagsOffset : off+elfPhdrFlagsOffset+4])
		va := binary.LittleEndian.Uint64(out[off+elfPhdrVAddrOffset : off+elfPhdrVAddrOffset+8])
		if (flags&elfPF_X) != 0 && va == uint64(plan.TextRVA) {
			textPhdrOff = off
			break
		}
	}
	if textPhdrOff == 0 {
		return nil, ErrNoTextSection
	}
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
	// Slot at newPhdrOff is already zero: it lies beyond the copy(out, input)
	// region (input ends at plan.StubFileOff-ish; make zeroes the tail).
	binary.LittleEndian.PutUint32(out[newPhdrOff:newPhdrOff+4], elfPT_LOAD)
	binary.LittleEndian.PutUint32(out[newPhdrOff+elfPhdrFlagsOffset:newPhdrOff+elfPhdrFlagsOffset+4], elfPF_R|elfPF_X)
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrOffsetOffset:newPhdrOff+elfPhdrOffsetOffset+8], uint64(plan.StubFileOff))
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrVAddrOffset:newPhdrOff+elfPhdrVAddrOffset+8], uint64(plan.StubRVA))
	binary.LittleEndian.PutUint64(out[newPhdrOff+0x18:newPhdrOff+0x20], uint64(plan.StubRVA)) // p_paddr = vaddr
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrFileSzOffset:newPhdrOff+elfPhdrFileSzOffset+8], uint64(plan.StubMaxSize))
	binary.LittleEndian.PutUint64(out[newPhdrOff+elfPhdrMemSzOffset:newPhdrOff+elfPhdrMemSzOffset+8], uint64(plan.StubMaxSize))
	binary.LittleEndian.PutUint64(out[newPhdrOff+0x30:newPhdrOff+0x38], elfPageSize)

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

func alignUpU64(v, align uint64) uint64 {
	return (v + align - 1) &^ (align - 1)
}
