// cover_imports.go — fake IMAGE_IMPORT_DESCRIPTOR entries (cover-layer v2).
//
// AddFakeImportsPE appends fake Import Directory entries for benign
// Windows DLLs so static analyzers see a richer import surface.
// The kernel resolves each entry at load time (the DLLs must exist
// and the function names must be real exports); the IAT slots are
// populated but the binary's code never references them.
//
// Architecture (PE/COFF Spec Rev 12.0 § 6.4):
//
//  1. Read the existing IMAGE_IMPORT_DESCRIPTOR array + their ILT
//     bodies from DataDirectory[1].
//  2. Build a new self-contained section containing:
//     [merged descriptor array]
//     [existing ILTs (copied from original)]
//     [fake ILTs]
//     [fake IATs]
//     [fake Hint/Name table]
//     [fake DLL name strings]
//     [existing DLL name strings (copied from original)]
//     All RVAs inside existing descriptors are updated so that
//     OriginalFirstThunk points into the new section; FirstThunk
//     is preserved verbatim (the loader patches IAT via FirstThunk,
//     so it must remain at its linker-baked address).
//  3. Append the new section via the same section-table-grow logic
//     used by AddCoverPE.
//  4. Patch DataDirectory[1] RVA → start of new section, Size updated.
//
// Self-containment requirement: debug/pe.ImportedSymbols() loads
// the section identified by DataDirectory[1] into a single buffer,
// then resolves all OriginalFirstThunk RVAs as offsets within that
// buffer. Every RVA (OFT, DLL name, Hint/Name) must therefore fall
// inside the new section's [VA, VA+VSize) range.
//
// MITRE: T1027 (Obfuscated Files or Information) / T1027.005
// (Indicator Removal from Tools).

package packer

import (
	"encoding/binary"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// IMAGE_IMPORT_DESCRIPTOR layout constants from PE/COFF Spec Rev 12.0 § 6.4.
const (
	importDescriptorSize = 20 // bytes per IMAGE_IMPORT_DESCRIPTOR

	// Field offsets inside IMAGE_IMPORT_DESCRIPTOR.
	iidOriginalFirstThunk = 0x00 // RVA of Import Lookup Table
	iidForwarderChain     = 0x08 // 0xFFFFFFFF
	iidName               = 0x0C // RVA of DLL name string
	iidFirstThunk         = 0x10 // RVA of Import Address Table

	// iltEntrySize64 is the size of one PE32+ ILT/IAT entry (8 bytes).
	iltEntrySize64 = 8

	// hintNameHeaderSize is the u16 Hint field that precedes each
	// function name in an IMAGE_IMPORT_BY_NAME structure.
	hintNameHeaderSize = 2

	// optDataDirsImportIdx is the DataDirectory index for the Import
	// Directory (PE/COFF Spec § 6.4).
	optDataDirsImportIdx = 1

	// optDataDirsBaseOffset is the byte offset of the first
	// DataDirectory entry relative to the Optional Header start.
	// Confirmed by optDataDirsStart = 0x70 in transform/pe.go.
	optDataDirsBaseOffset = 0x70
)

// FakeImport describes one DLL and its function list to add as a
// fake import entry. The DLL name and function names must be real
// exports on the target Windows version — the kernel rejects any
// name that cannot be resolved at load time.
type FakeImport struct {
	DLL       string   // e.g. "kernel32.dll"
	Functions []string // e.g. ["Sleep", "GetCurrentThreadId"]
}

// DefaultFakeImports is a ready-to-use list of real Windows 10
// 1809+ / Server 2019+ imports. All four DLLs ship in every
// supported Windows installation; all function names are stable
// exports verified against Microsoft public symbol tables.
var DefaultFakeImports = []FakeImport{
	{DLL: "kernel32.dll", Functions: []string{"Sleep", "GetCurrentThreadId"}},
	{DLL: "user32.dll", Functions: []string{"MessageBoxA", "GetCursorPos"}},
	{DLL: "shell32.dll", Functions: []string{"ShellExecuteA"}},
	{DLL: "ole32.dll", Functions: []string{"CoInitialize"}},
}

// AddFakeImportsPE appends fake IMAGE_IMPORT_DESCRIPTOR entries to
// input (a PE32+ produced by PackBinary or AddCoverPE). The merged
// Import Directory — original entries followed by one entry per
// FakeImport, terminated by a zero descriptor — is placed in a new
// R-only section named ".idata2". DataDirectory[1] is patched to
// point at the new section.
//
// Existing entries' FirstThunk RVAs are preserved verbatim — the
// loader patches those addresses, and the binary's code references
// them. OriginalFirstThunk is updated to point into the new section
// (the ILT body for existing entries is copied there) so the entire
// Import Directory is self-contained within the new section.
//
// fakes must contain at least one entry; every DLL name and function
// name must be resolvable on the target OS or the kernel will reject
// the image at load time.
//
// Returns ErrCoverInvalidOptions when fakes is empty or input is
// not a PE32+. Returns ErrCoverSectionTableFull when the section
// header table has no slack for an additional entry.
func AddFakeImportsPE(input []byte, fakes []FakeImport) ([]byte, error) {
	if len(fakes) == 0 {
		return nil, ErrCoverInvalidOptions
	}
	if !bytesAreLikelyPE(input) {
		return nil, fmt.Errorf("%w: not a PE32+ (no MZ/PE)", ErrCoverInvalidOptions)
	}

	// Parse PE header fields needed for section placement.
	peOff := binary.LittleEndian.Uint32(input[transform.PEELfanewOffset : transform.PEELfanewOffset+4])
	coffOff := peOff + transform.PESignatureSize
	numSections := binary.LittleEndian.Uint16(input[coffOff+transform.COFFNumSectionsOffset : coffOff+transform.COFFNumSectionsOffset+2])
	sizeOfOptHdr := binary.LittleEndian.Uint16(input[coffOff+transform.COFFSizeOfOptHdrOffset : coffOff+transform.COFFSizeOfOptHdrOffset+2])
	optOff := coffOff + transform.PECOFFHdrSize

	sectionAlign := binary.LittleEndian.Uint32(input[optOff+transform.OptSectionAlignOffset : optOff+transform.OptSectionAlignOffset+4])
	fileAlign := binary.LittleEndian.Uint32(input[optOff+transform.OptFileAlignOffset : optOff+transform.OptFileAlignOffset+4])
	sizeOfImage := binary.LittleEndian.Uint32(input[optOff+transform.OptSizeOfImageOffset : optOff+transform.OptSizeOfImageOffset+4])

	sectionTableOff := uint32(optOff) + uint32(sizeOfOptHdr)

	// Walk the existing section table to find placement for the new section.
	var maxRVAEnd, maxRawEnd uint32
	firstSecRaw := uint32(0xFFFFFFFF)
	for i := uint16(0); i < numSections; i++ {
		hdr := sectionTableOff + uint32(i)*transform.PESectionHdrSize
		va := binary.LittleEndian.Uint32(input[hdr+transform.SecVirtualAddressOffset : hdr+transform.SecVirtualAddressOffset+4])
		vSize := binary.LittleEndian.Uint32(input[hdr+transform.SecVirtualSizeOffset : hdr+transform.SecVirtualSizeOffset+4])
		raw := binary.LittleEndian.Uint32(input[hdr+transform.SecPointerToRawDataOffset : hdr+transform.SecPointerToRawDataOffset+4])
		rawSize := binary.LittleEndian.Uint32(input[hdr+transform.SecSizeOfRawDataOffset : hdr+transform.SecSizeOfRawDataOffset+4])
		if e := transform.AlignUpU32(va+vSize, sectionAlign); e > maxRVAEnd {
			maxRVAEnd = e
		}
		if e := raw + rawSize; e > maxRawEnd {
			maxRawEnd = e
		}
		if raw < firstSecRaw {
			firstSecRaw = raw
		}
	}

	// Reject if there is no slot for the new section header.
	newHdrOff := sectionTableOff + uint32(numSections)*transform.PESectionHdrSize
	if newHdrOff+transform.PESectionHdrSize > firstSecRaw {
		return nil, ErrCoverSectionTableFull
	}

	secRVA := transform.AlignUpU32(maxRVAEnd, sectionAlign)
	secRaw := transform.AlignUpU32(maxRawEnd, fileAlign)

	// Collect existing import data; secRVA required to rewrite OFT RVAs.
	existing := parseExistingImports(input, sectionTableOff, numSections, optOff)

	// Build the merged import section body — fully self-contained.
	secBody := buildImportSection(existing, fakes, secRVA)

	secVirtualSize := uint32(len(secBody))
	secRawSize := transform.AlignUpU32(secVirtualSize, fileAlign)

	totalSize := secRaw + secRawSize
	if uint32(len(input)) > totalSize {
		totalSize = uint32(len(input))
	}
	out := make([]byte, totalSize)
	copy(out, input)

	copy(out[secRaw:secRaw+secVirtualSize], secBody)

	// Write new section header (".idata2" — standard name for a secondary
	// import directory, recognised by debuggers as benign import data).
	copy(out[newHdrOff:newHdrOff+8], ".idata2\x00")
	binary.LittleEndian.PutUint32(out[newHdrOff+transform.SecVirtualSizeOffset:newHdrOff+transform.SecVirtualSizeOffset+4], secVirtualSize)
	binary.LittleEndian.PutUint32(out[newHdrOff+transform.SecVirtualAddressOffset:newHdrOff+transform.SecVirtualAddressOffset+4], secRVA)
	binary.LittleEndian.PutUint32(out[newHdrOff+transform.SecSizeOfRawDataOffset:newHdrOff+transform.SecSizeOfRawDataOffset+4], secRawSize)
	binary.LittleEndian.PutUint32(out[newHdrOff+transform.SecPointerToRawDataOffset:newHdrOff+transform.SecPointerToRawDataOffset+4], secRaw)
	binary.LittleEndian.PutUint32(out[newHdrOff+transform.SecCharacteristicsOffset:newHdrOff+transform.SecCharacteristicsOffset+4], transform.ScnMemReadInitData)

	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFNumSectionsOffset:coffOff+transform.COFFNumSectionsOffset+2], numSections+1)

	newSizeOfImage := transform.AlignUpU32(secRVA+secVirtualSize, sectionAlign)
	if newSizeOfImage > sizeOfImage {
		binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfImageOffset:optOff+transform.OptSizeOfImageOffset+4], newSizeOfImage)
	}

	// Patch DataDirectory[1]: RVA = secRVA, Size = total descriptor table
	// including zero terminator (DataDirectory.Size field per spec is the
	// byte size of the descriptor array, not the full import section).
	importDirSize := uint32(len(existing)+len(fakes)+1) * importDescriptorSize
	importDataDirOff := uint32(optOff) + optDataDirsBaseOffset + optDataDirsImportIdx*8
	binary.LittleEndian.PutUint32(out[importDataDirOff:importDataDirOff+4], secRVA)
	binary.LittleEndian.PutUint32(out[importDataDirOff+4:importDataDirOff+8], importDirSize)

	return out, nil
}

// existingImport carries the data for one descriptor read from the
// original import directory, enough to re-emit it in a self-contained
// new section.
type existingImport struct {
	firstThunk uint32 // preserved verbatim — loader patches this
	dllName    string // for the DLL name string in the new section
	iltRaw     []byte // raw ILT bytes (including zero terminator entry)
}

// parseExistingImports reads each IMAGE_IMPORT_DESCRIPTOR from
// DataDirectory[1], follows OriginalFirstThunk to collect the ILT
// bytes and the DLL name. Returns nil if no imports are present.
func parseExistingImports(input []byte, sectionTableOff uint32, numSections uint16, optOff uint32) []existingImport {
	importDataDirOff := optOff + optDataDirsBaseOffset + optDataDirsImportIdx*8
	if int(importDataDirOff)+8 > len(input) {
		return nil
	}
	importRVA := binary.LittleEndian.Uint32(input[importDataDirOff : importDataDirOff+4])
	if importRVA == 0 {
		return nil
	}
	descFileOff, ok := rvaToFileOffset(input, sectionTableOff, numSections, importRVA)
	if !ok {
		return nil
	}

	var result []existingImport
	for {
		base := descFileOff + uint32(len(result))*importDescriptorSize
		if int(base)+importDescriptorSize > len(input) {
			break
		}
		oft := binary.LittleEndian.Uint32(input[base+iidOriginalFirstThunk : base+iidOriginalFirstThunk+4])
		ft := binary.LittleEndian.Uint32(input[base+iidFirstThunk : base+iidFirstThunk+4])
		if oft == 0 && ft == 0 {
			break
		}

		nameRVA := binary.LittleEndian.Uint32(input[base+iidName : base+iidName+4])
		dllName := readCString(input, sectionTableOff, numSections, nameRVA)

		// Collect ILT entries including the zero terminator.
		iltRaw := readILT(input, sectionTableOff, numSections, oft)

		result = append(result, existingImport{
			firstThunk: ft,
			dllName:    dllName,
			iltRaw:     iltRaw,
		})
	}
	return result
}

// hintEntrySize returns the byte size of one IMAGE_IMPORT_BY_NAME
// record for the given function name: 2-byte Hint + name + NUL,
// padded to an even byte count per PE/COFF Spec § 6.4.
func hintEntrySize(name string) uint32 {
	sz := hintNameHeaderSize + len(name) + 1
	if sz%2 != 0 {
		sz++
	}
	return uint32(sz)
}

// buildImportSection constructs the raw bytes for a fully
// self-contained new PE section. Layout:
//
//	[0]                  descriptor array (existing + fake + zero terminator)
//	[descArraySize]      existing ILTs (copied verbatim)
//	[existILTsEnd]       fake ILTs
//	[fakeILTsEnd]        fake IATs (mirror of fake ILTs before kernel fix-up)
//	[fakeIATsEnd]        fake Hint/Name table
//	[hintNamesEnd]       fake DLL name strings
//	[fakeDLLNamesEnd]    existing DLL name strings
//
// secRVA is the virtual address at which the new section will be mapped.
func buildImportSection(existing []existingImport, fakes []FakeImport, secRVA uint32) []byte {
	totalDescriptors := len(existing) + len(fakes) + 1 // +1 zero terminator
	descArraySize := uint32(totalDescriptors * importDescriptorSize)

	// Single pass over existing: sum ILT bytes + DLL name bytes.
	existILTsSize, existDLLNamesSize := uint32(0), uint32(0)
	for _, ei := range existing {
		existILTsSize += uint32(len(ei.iltRaw))
		existDLLNamesSize += uint32(len(ei.dllName)) + 1
	}

	// Single pass over fakes: sum ILT entry count, hint/name bytes, DLL name bytes.
	// Each DLL contributes len(Functions) ILT entries + 1 zero terminator.
	fakeILTEntries, hintNamesSize, fakeDLLNamesSize := uint32(0), uint32(0), uint32(0)
	for _, fi := range fakes {
		fakeILTEntries += uint32(len(fi.Functions)) + 1 // +1 zero terminator per DLL
		for _, fn := range fi.Functions {
			hintNamesSize += hintEntrySize(fn)
		}
		fakeDLLNamesSize += uint32(len(fi.DLL)) + 1
	}
	fakeILTSize := fakeILTEntries * iltEntrySize64
	fakeIATSize := fakeILTSize

	secSize := descArraySize + existILTsSize + fakeILTSize + fakeIATSize + hintNamesSize + fakeDLLNamesSize + existDLLNamesSize
	sec := make([]byte, secSize)

	existILTsBase := descArraySize
	fakeILTsBase := existILTsBase + existILTsSize
	fakeIATsBase := fakeILTsBase + fakeILTSize
	hintNamesBase := fakeIATsBase + fakeIATSize
	fakeDLLNamesBase := hintNamesBase + hintNamesSize
	existDLLNamesBase := fakeDLLNamesBase + fakeDLLNamesSize

	// --- Existing descriptors ---
	// Copy ILTs into the new section; update OriginalFirstThunk to the
	// new location. FirstThunk stays at its original RVA (loader target).
	// DLL Name RVA is rewritten to point at the copy in the new section.
	existILTCursor := uint32(0)
	existDLLNameCursor := uint32(0)
	for i, ei := range existing {
		descOff := uint32(i) * importDescriptorSize

		// New ILT location inside this section.
		newOFT := secRVA + existILTsBase + existILTCursor
		// FirstThunk preserved — loader patches IAT via this address.
		newFT := ei.firstThunk
		// New DLL name location inside this section.
		newNameRVA := secRVA + existDLLNamesBase + existDLLNameCursor

		binary.LittleEndian.PutUint32(sec[descOff+iidOriginalFirstThunk:descOff+iidOriginalFirstThunk+4], newOFT)
		// TimeDateStamp (offset 0x04) left zero by make.
		binary.LittleEndian.PutUint32(sec[descOff+iidForwarderChain:descOff+iidForwarderChain+4], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(sec[descOff+iidName:descOff+iidName+4], newNameRVA)
		binary.LittleEndian.PutUint32(sec[descOff+iidFirstThunk:descOff+iidFirstThunk+4], newFT)

		// Copy ILT body.
		copy(sec[existILTsBase+existILTCursor:], ei.iltRaw)
		existILTCursor += uint32(len(ei.iltRaw))

		// Copy DLL name string.
		copy(sec[existDLLNamesBase+existDLLNameCursor:], ei.dllName)
		existDLLNameCursor += uint32(len(ei.dllName)) + 1
	}

	// --- Fake descriptors ---
	var fakeILTCursor, hintCursor, fakeDLLNameCursor uint32
	for i, fi := range fakes {
		descOff := uint32(len(existing)+i) * importDescriptorSize

		iltRVA := secRVA + fakeILTsBase + fakeILTCursor*iltEntrySize64
		iatRVA := secRVA + fakeIATsBase + fakeILTCursor*iltEntrySize64
		dllNameRVA := secRVA + fakeDLLNamesBase + fakeDLLNameCursor

		binary.LittleEndian.PutUint32(sec[descOff+iidOriginalFirstThunk:descOff+iidOriginalFirstThunk+4], iltRVA)
		// TimeDateStamp zero by make.
		binary.LittleEndian.PutUint32(sec[descOff+iidForwarderChain:descOff+iidForwarderChain+4], 0xFFFFFFFF)
		binary.LittleEndian.PutUint32(sec[descOff+iidName:descOff+iidName+4], dllNameRVA)
		binary.LittleEndian.PutUint32(sec[descOff+iidFirstThunk:descOff+iidFirstThunk+4], iatRVA)

		for _, fn := range fi.Functions {
			hintNameRVA := secRVA + hintNamesBase + hintCursor

			iltOff := fakeILTsBase + fakeILTCursor*iltEntrySize64
			binary.LittleEndian.PutUint64(sec[iltOff:iltOff+8], uint64(hintNameRVA))

			iatOff := fakeIATsBase + fakeILTCursor*iltEntrySize64
			binary.LittleEndian.PutUint64(sec[iatOff:iatOff+8], uint64(hintNameRVA))

			// IMAGE_IMPORT_BY_NAME: Hint=0 (u16), then function name + NUL.
			hnOff := hintNamesBase + hintCursor
			binary.LittleEndian.PutUint16(sec[hnOff:hnOff+2], 0)
			copy(sec[hnOff+2:], fn)
			hintCursor += hintEntrySize(fn)
			fakeILTCursor++
		}
		// Per-DLL zero ILT/IAT terminator already zero from make.
		fakeILTCursor++

		copy(sec[fakeDLLNamesBase+fakeDLLNameCursor:], fi.DLL)
		fakeDLLNameCursor += uint32(len(fi.DLL)) + 1
	}
	// Zero-terminator descriptor already zero from make.

	return sec
}

// readILT returns the raw ILT bytes for the descriptor whose
// OriginalFirstThunk is iltRVA, including the 8-byte zero terminator.
// Returns nil when the RVA cannot be resolved.
func readILT(input []byte, sectionTableOff uint32, numSections uint16, iltRVA uint32) []byte {
	fileOff, ok := rvaToFileOffset(input, sectionTableOff, numSections, iltRVA)
	if !ok {
		return nil
	}
	// Walk 8-byte PE32+ ILT entries until the zero terminator.
	n := 0
	for {
		off := fileOff + uint32(n)*iltEntrySize64
		if int(off)+iltEntrySize64 > len(input) {
			break
		}
		va := binary.LittleEndian.Uint64(input[off : off+8])
		n++
		if va == 0 {
			break
		}
	}
	raw := make([]byte, n*iltEntrySize64)
	copy(raw, input[fileOff:fileOff+uint32(n)*iltEntrySize64])
	return raw
}

// readCString resolves nameRVA to a file offset and reads a
// null-terminated ASCII string. Returns "" if unresolvable.
func readCString(input []byte, sectionTableOff uint32, numSections uint16, nameRVA uint32) string {
	fileOff, ok := rvaToFileOffset(input, sectionTableOff, numSections, nameRVA)
	if !ok {
		return ""
	}
	end := fileOff
	for int(end) < len(input) && input[end] != 0 {
		end++
	}
	return string(input[fileOff:end])
}

// rvaToFileOffset translates an RVA to a file offset by walking the
// PE section table. Returns (offset, true) when the RVA falls inside
// a known section, (0, false) otherwise.
func rvaToFileOffset(input []byte, sectionTableOff uint32, numSections uint16, rva uint32) (uint32, bool) {
	for i := uint16(0); i < numSections; i++ {
		hdr := sectionTableOff + uint32(i)*transform.PESectionHdrSize
		if int(hdr)+transform.PESectionHdrSize > len(input) {
			break
		}
		va := binary.LittleEndian.Uint32(input[hdr+transform.SecVirtualAddressOffset : hdr+transform.SecVirtualAddressOffset+4])
		vSize := binary.LittleEndian.Uint32(input[hdr+transform.SecVirtualSizeOffset : hdr+transform.SecVirtualSizeOffset+4])
		rawOff := binary.LittleEndian.Uint32(input[hdr+transform.SecPointerToRawDataOffset : hdr+transform.SecPointerToRawDataOffset+4])
		if rva >= va && rva < va+vSize {
			return rawOff + (rva - va), true
		}
	}
	return 0, false
}
