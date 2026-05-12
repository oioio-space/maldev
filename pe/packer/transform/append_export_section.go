package transform

import (
	"encoding/binary"
	"fmt"
)

// dirExport is the DataDirectory index for the export table.
const dirExport = 0

// defaultExportSectionName is the section name used when an
// operator doesn't supply a custom one. Mimics MSVC's emit so
// the appended section blends in.
var defaultExportSectionName = [8]byte{'.', 'e', 'd', 'a', 't', 'a', 0, 0}

// AppendExportSection adds a new section carrying `exportBytes`
// to the end of `pe`'s section list and points
// DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] at it.
//
// `exportBytes` MUST have been produced by
// [github.com/oioio-space/maldev/pe/dllproxy.BuildExportData] with
// `sectionVA` matching the RVA the new section will land at.
// AppendExportSection computes that RVA from the existing PE
// layout (next aligned RVA after the last section) — callers
// using [packer.PackProxyDLL] don't need to compute it
// themselves; the orchestrator threads the value through.
//
// Used by [packer.PackProxyDLL] (slice 6 Path B) to fuse a
// converted-EXE-as-DLL output with proxy-style export forwarders
// in a single PE.
//
// Section is named `.edata` (mimics MSVC). Operators wanting a
// custom name can post-patch the section header — only one
// section header is touched.
//
// Returns the modified buffer (fresh allocation; input is not
// mutated). Returns [ErrSectionTableFull] when there's no
// headroom for one more section header.
func AppendExportSection(pe []byte, exportBytes []byte, sectionRVA uint32) ([]byte, error) {
	l, err := parsePELayout(pe)
	if err != nil {
		return nil, err
	}
	fileAlign := binary.LittleEndian.Uint32(pe[l.optOff+OptFileAlignOffset:])
	sectionAlign := binary.LittleEndian.Uint32(pe[l.optOff+OptSectionAlignOffset:])
	sizeOfHeaders := binary.LittleEndian.Uint32(pe[l.optOff+OptSizeOfHeadersOffset:])
	if fileAlign == 0 || sectionAlign == 0 {
		return nil, fmt.Errorf("transform: AppendExportSection: zero alignment in PE")
	}

	// Section table headroom: one more 40-byte entry.
	newHdrEnd := uint64(l.secTableOff) + uint64(uint32(int(l.numSections)+1))*uint64(PESectionHdrSize)
	if newHdrEnd > uint64(sizeOfHeaders) {
		return nil, fmt.Errorf("%w: appending export section needs %d header bytes, have %d",
			ErrSectionTableFull, newHdrEnd, sizeOfHeaders)
	}

	exportFileOff := AlignUpU32(uint32(len(pe)), fileAlign)
	exportFileSize := AlignUpU32(uint32(len(exportBytes)), fileAlign)
	totalSize := exportFileOff + exportFileSize

	out := make([]byte, totalSize)
	copy(out, pe)
	copy(out[exportFileOff:exportFileOff+uint32(len(exportBytes))], exportBytes)

	// Append the section header.
	newHdrOff := l.secTableOff + uint32(l.numSections)*PESectionHdrSize
	copy(out[newHdrOff:newHdrOff+8], defaultExportSectionName[:])
	binary.LittleEndian.PutUint32(out[newHdrOff+SecVirtualSizeOffset:], uint32(len(exportBytes)))
	binary.LittleEndian.PutUint32(out[newHdrOff+SecVirtualAddressOffset:], sectionRVA)
	binary.LittleEndian.PutUint32(out[newHdrOff+SecSizeOfRawDataOffset:], exportFileSize)
	binary.LittleEndian.PutUint32(out[newHdrOff+SecPointerToRawDataOffset:], exportFileOff)
	binary.LittleEndian.PutUint32(out[newHdrOff+SecCharacteristicsOffset:], ScnCntInitData|ScnMemRead)

	// Bump NumberOfSections.
	binary.LittleEndian.PutUint16(
		out[l.coffOff+COFFNumSectionsOffset:],
		l.numSections+1)

	// Update DataDirectory[EXPORT] + SizeOfImage.
	dirEntryOff := l.optOff + OptDataDirsStart + dirExport*OptDataDirEntrySize
	binary.LittleEndian.PutUint32(out[dirEntryOff:], sectionRVA)
	binary.LittleEndian.PutUint32(out[dirEntryOff+4:], uint32(len(exportBytes)))

	newSizeOfImage := AlignUpU32(sectionRVA+uint32(len(exportBytes)), sectionAlign)
	binary.LittleEndian.PutUint32(out[l.optOff+OptSizeOfImageOffset:], newSizeOfImage)

	return out, nil
}

// NextAvailableRVA returns the RVA where a new section appended
// to `pe` would land — the section-aligned end of the
// highest-VA section currently in the section table.
//
// Used by [packer.PackProxyDLL] to compute the RVA to bake into
// [github.com/oioio-space/maldev/pe/dllproxy.BuildExportData] before
// calling [AppendExportSection].
func NextAvailableRVA(pe []byte) (uint32, error) {
	l, err := parsePELayout(pe)
	if err != nil {
		return 0, err
	}
	sectionAlign := binary.LittleEndian.Uint32(pe[l.optOff+OptSectionAlignOffset:])
	if sectionAlign == 0 {
		return 0, fmt.Errorf("transform: NextAvailableRVA: zero SectionAlignment")
	}
	var maxEnd uint32
	for i := uint16(0); i < l.numSections; i++ {
		hdrOff := l.secTableOff + uint32(i)*PESectionHdrSize
		va := binary.LittleEndian.Uint32(pe[hdrOff+SecVirtualAddressOffset:])
		vs := binary.LittleEndian.Uint32(pe[hdrOff+SecVirtualSizeOffset:])
		end := AlignUpU32(va+vs, sectionAlign)
		if end > maxEnd {
			maxEnd = end
		}
	}
	return maxEnd, nil
}
