package transform

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// AppendJunkSeparators returns a fresh buffer with `count`
// uninitialised "separator" section headers appended AFTER the
// existing sections (which the packer convention places the stub
// at). Each separator is BSS-style: SizeOfRawData=0,
// PointerToRawData=0, IMAGE_SCN_CNT_UNINITIALIZED_DATA |
// IMAGE_SCN_MEM_READ. File size unchanged — only SizeOfImage
// and NumberOfSections grow. The stub keeps its VA + table slot;
// separator VAs run upward from `alignUp(stubVA+stubVS,
// SectionAlignment)`. Critical: the stub must NOT move because
// its body uses RIP-relative addressing baked at stubgen time.
//
// count<=0 is a no-op (returns a fresh copy of the input).
// Returns [ErrSectionTableFull] when SizeOfHeaders has no room
// for `count` more 40-byte entries.
func AppendJunkSeparators(pe []byte, count int, rng *rand.Rand) ([]byte, error) {
	if count <= 0 {
		out := make([]byte, len(pe))
		copy(out, pe)
		return out, nil
	}
	l, err := parsePELayout(pe)
	if err != nil {
		return nil, err
	}
	if l.numSections == 0 {
		return nil, fmt.Errorf("transform: cannot insert separators into PE with zero sections")
	}

	sectionAlign := binary.LittleEndian.Uint32(pe[l.optOff+OptSectionAlignOffset:])
	sizeOfHeaders := binary.LittleEndian.Uint32(pe[l.optOff+OptSizeOfHeadersOffset:])
	if sectionAlign == 0 {
		return nil, fmt.Errorf("transform: SectionAlignment is zero")
	}

	// Section table headroom: each new entry is 40 bytes.
	newTableEnd := uint64(l.secTableOff) + uint64(uint32(int(l.numSections)+count))*uint64(PESectionHdrSize)
	if newTableEnd > uint64(sizeOfHeaders) {
		return nil, fmt.Errorf("%w: need %d bytes, have %d",
			ErrSectionTableFull, newTableEnd, sizeOfHeaders)
	}

	// Stub is the last section per the InjectStubPE convention.
	// Compute the next VA past the stub — separators start there.
	lastIdx := l.numSections - 1
	stubHdrOff := l.secTableOff + uint32(lastIdx)*PESectionHdrSize
	stubVA := binary.LittleEndian.Uint32(pe[stubHdrOff+SecVirtualAddressOffset:])
	stubVS := binary.LittleEndian.Uint32(pe[stubHdrOff+SecVirtualSizeOffset:])
	nextVA := alignUpU32(stubVA+stubVS, sectionAlign)

	out := make([]byte, len(pe))
	copy(out, pe)

	// Append `count` separator headers AFTER the stub at table
	// positions [numSections, numSections+count-1]. Separator VAs
	// > stub VA so the section table stays sorted ascending. The
	// stub header is untouched — preserves OEP + RIP-relative
	// addressing inside the stub body.
	used := make([][8]byte, 0, count)
	for i := 0; i < count; i++ {
		hdrOff := l.secTableOff + uint32(int(l.numSections)+i)*PESectionHdrSize
		var hdr [PESectionHdrSize]byte
		name := RandomUniqueSectionName(rng, used)
		used = append(used, name)
		copy(hdr[0:8], name[:])
		binary.LittleEndian.PutUint32(hdr[SecVirtualSizeOffset:], sectionAlign)
		binary.LittleEndian.PutUint32(hdr[SecVirtualAddressOffset:], nextVA+uint32(i)*sectionAlign)
		// SizeOfRawData=0, PointerToRawData=0 → uninitialised BSS,
		// loader zero-fills the VA span without touching the file.
		binary.LittleEndian.PutUint32(hdr[SecCharacteristicsOffset:], ScnCntUninitData|ScnMemRead)
		copy(out[hdrOff:hdrOff+PESectionHdrSize], hdr[:])
	}

	// Bump NumberOfSections + SizeOfImage. SizeOfImage must cover
	// the highest-VA separator's full virtual span.
	binary.LittleEndian.PutUint16(
		out[l.coffOff+COFFNumSectionsOffset:],
		l.numSections+uint16(count))
	highestSeparatorEnd := nextVA + uint32(count)*sectionAlign
	binary.LittleEndian.PutUint32(out[l.optOff+OptSizeOfImageOffset:], highestSeparatorEnd)

	return out, nil
}
