package transform

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// CharRelocsStripped is IMAGE_FILE_RELOCS_STRIPPED — set in COFF
// Characteristics when the linker dropped the .reloc table. PEs
// with this bit set cannot be rebased; ShiftImageVA returns
// ErrRelocsStripped on them.
const CharRelocsStripped uint16 = 0x0001

// ErrRelocsStripped fires when ShiftImageVA is called on a PE
// whose COFF Characteristics has IMAGE_FILE_RELOCS_STRIPPED set.
// Such images can't be relocated — the linker dropped the
// metadata needed to fix up absolute pointers.
var ErrRelocsStripped = errors.New("transform: COFF IMAGE_FILE_RELOCS_STRIPPED is set")

// CharOff is the offset of the COFF Characteristics field
// inside the COFF File Header (uint16).
const CharOff = 0x12

// ShiftImageVA bumps every section's VirtualAddress by `delta`
// bytes (must be a positive multiple of SectionAlignment), then
// fixes up every place in the image that records a VA: the OEP,
// BaseOfCode, the DataDirectory entries' top-level RVAs, the
// base-relocation table (each block's PageRVA + the absolute
// pointer values it patches), SizeOfImage, and SizeOfHeaders.
// Section data is NOT moved — only metadata.
//
// Inter-section deltas are preserved, so RIP-relative
// references between sections keep working without re-encoding.
//
// **Known limitation (2026-05-11):** does NOT yet walk the
// internal RVA fields inside per-directory structures (import
// descriptors' OriginalFirstThunk/Name/FirstThunk, exception
// data RUNTIME_FUNCTION entries, export tables, resource trees,
// load-config, debug). PEs with non-trivial imports or exception
// data will load but fail at import resolution
// (STATUS_DLL_NOT_FOUND) or RtlAddFunctionTable. Use only on
// PEs validated to have empty/trivial directories, or compose
// with directory-walker passes when those are added. The
// PackBinary wiring keeps this opt OFF by default for that
// reason; RandomizeAll does NOT enable it.
//
// Phase 2-F-3-c (partial) of docs/refactor-2026-doc/packer-design.md.
//
// Returns ErrRelocsStripped when the input PE has
// IMAGE_FILE_RELOCS_STRIPPED set in COFF Characteristics — such
// images carry no relocation metadata and can't be safely
// shifted. Returns the input unchanged on delta == 0. The input
// slice is never mutated; a fresh buffer is returned.
func ShiftImageVA(pe []byte, delta uint32) ([]byte, error) {
	if delta == 0 {
		out := make([]byte, len(pe))
		copy(out, pe)
		return out, nil
	}
	l, err := parsePELayout(pe)
	if err != nil {
		return nil, err
	}
	chars := binary.LittleEndian.Uint16(pe[l.coffOff+CharOff:])
	if chars&CharRelocsStripped != 0 {
		return nil, ErrRelocsStripped
	}
	sectionAlign := binary.LittleEndian.Uint32(pe[l.optOff+OptSectionAlignOffset:])
	if sectionAlign == 0 {
		return nil, fmt.Errorf("transform: SectionAlignment is zero")
	}
	if delta%sectionAlign != 0 {
		return nil, fmt.Errorf("transform: delta 0x%x not a multiple of SectionAlignment 0x%x",
			delta, sectionAlign)
	}

	out := make([]byte, len(pe))
	copy(out, pe)

	// 1. Bump every section's VirtualAddress (NOT VirtualSize,
	//    NOT PointerToRawData — file layout untouched).
	//    Snapshot per-section old VA + VS first so the reloc
	//    fixup pass below can resolve RVAs against the OLD
	//    layout when classifying which section a pointer
	//    target lives in.
	ranges := make([]secRange, l.numSections)
	for i := uint16(0); i < l.numSections; i++ {
		hdrOff := l.secTableOff + uint32(i)*PESectionHdrSize
		va := binary.LittleEndian.Uint32(pe[hdrOff+SecVirtualAddressOffset:])
		vs := binary.LittleEndian.Uint32(pe[hdrOff+SecVirtualSizeOffset:])
		ranges[i] = secRange{oldVA: va, oldVS: vs}
		binary.LittleEndian.PutUint32(out[hdrOff+SecVirtualAddressOffset:], va+delta)
	}

	// 2. Bump OEP and BaseOfCode (both are RVAs in the Optional
	//    Header). BaseOfCode (+0x14) points at the start of the
	//    code section; the kernel uses it during initial PE
	//    validation and rejects with "not a valid Win32 application"
	//    if it doesn't fall in any section's VA range.
	oepOff := l.optOff + OptAddrEntryOffset
	if oep := binary.LittleEndian.Uint32(out[oepOff:]); oep != 0 {
		binary.LittleEndian.PutUint32(out[oepOff:], oep+delta)
	}
	const optBaseOfCodeOffset = 0x14
	bocOff := l.optOff + optBaseOfCodeOffset
	if boc := binary.LittleEndian.Uint32(out[bocOff:]); boc != 0 {
		binary.LittleEndian.PutUint32(out[bocOff:], boc+delta)
	}

	// 3. Bump every non-zero DataDirectory entry's RVA.
	for i := 0; i < 16; i++ {
		entryOff := l.optOff + OptDataDirsStart + uint32(i*OptDataDirEntrySize)
		if int(entryOff)+OptDataDirEntrySize > len(out) {
			break
		}
		rva := binary.LittleEndian.Uint32(out[entryOff:])
		if rva == 0 {
			continue
		}
		binary.LittleEndian.PutUint32(out[entryOff:], rva+delta)
	}

	// 4. Bump SizeOfImage so the loader's reservation covers the
	//    shifted-out tail. Without this the kernel rejects the
	//    image with ERROR_INVALID_IMAGE_FORMAT.
	sizeOfImageOff := l.optOff + OptSizeOfImageOffset
	soi := binary.LittleEndian.Uint32(out[sizeOfImageOff:])
	binary.LittleEndian.PutUint32(out[sizeOfImageOff:], soi+delta)

	// 4b. Bump SizeOfHeaders by `delta` so the virtual range
	//     [0, alignUp(SizeOfHeaders, SectionAlignment)) covers
	//     the gap [old_section0_VA, new_section0_VA). The
	//     kernel requires section[0].VA to equal alignUp(
	//     SizeOfHeaders, SectionAlignment) — without this bump
	//     it rejects the image as "not a valid Win32 application".
	//     File bytes don't grow; the loader zero-fills the
	//     virtual padding past file SizeOfHeaders bytes.
	sizeOfHeadersOff := l.optOff + OptSizeOfHeadersOffset
	soh := binary.LittleEndian.Uint32(out[sizeOfHeadersOff:])
	binary.LittleEndian.PutUint32(out[sizeOfHeadersOff:], soh+delta)

	// 5. Walk the base-relocation table:
	//    a) Each block's PageRVA += delta (the page being
	//       described moved by `delta`).
	//    b) Each entry patches an absolute pointer at some RVA.
	//       Read the value at that file offset, classify which
	//       section the OLD value's RVA lives in (= imageBase +
	//       targetRVA → targetRVA = value - imageBase), translate
	//       to new value (+ delta if the target is anywhere in
	//       the shifted image — which is always true since EVERY
	//       section moved). Write back.
	//
	//    Note: rvaToFileOff resolves against the section table.
	//    The headers in `out` already carry the NEW VAs, so we
	//    use a small inline resolver against the OLD ranges
	//    snapshot for entry-location lookups, and read/write
	//    pointer values directly (no resolver needed since the
	//    file offset was captured by the walker).
	// 5b. Walk the IMPORT directory and bump every internal RVA
	//     field. Without this the loader fails import resolution
	//     with STATUS_DLL_NOT_FOUND because import descriptor
	//     OriginalFirstThunk/Name/FirstThunk and the by-name
	//     thunks they point at are RVAs the linker bakes as raw
	//     uint32, NOT covered by the .reloc table.
	if walkErr := WalkImportDirectoryRVAs(pe, func(rvaFileOff uint32) error {
		if int(rvaFileOff)+4 > len(out) {
			return fmt.Errorf("import RVA patch past EOF (file 0x%x)", rvaFileOff)
		}
		cur := binary.LittleEndian.Uint32(out[rvaFileOff:])
		if cur == 0 {
			return nil
		}
		binary.LittleEndian.PutUint32(out[rvaFileOff:], cur+delta)
		return nil
	}); walkErr != nil {
		return nil, fmt.Errorf("transform: import directory fixup: %w", walkErr)
	}

	walkErr := WalkBaseRelocs(pe, func(e BaseRelocEntry) error {
		// (a) Repack the block's PageRVA in `out`. We do this
		//     once per block; the walker yields entries in
		//     ascending order so detect the first entry of a
		//     block via EntryIdx == 0.
		if e.EntryIdx == 0 {
			binary.LittleEndian.PutUint32(out[e.BlockOff:], e.BlockVA+delta)
		}
		// (b) Patch the absolute pointer value at the entry's
		//     target file location. The target RVA in OLD
		//     coordinates is `e.RVA`; translate to file offset
		//     via the OLD ranges snapshot.
		switch e.Type {
		case RelTypeAbsolute:
			return nil // padding entry; no patch
		case RelTypeDir64:
			fileOff, ferr := rvaToFileOffOld(out, l, ranges, e.RVA)
			if ferr != nil {
				return fmt.Errorf("dir64 reloc at RVA 0x%x: %w", e.RVA, ferr)
			}
			if int(fileOff)+8 > len(out) {
				return fmt.Errorf("dir64 reloc patch past EOF (RVA 0x%x → file 0x%x)", e.RVA, fileOff)
			}
			val := binary.LittleEndian.Uint64(out[fileOff:])
			// Stored value = imageBase + targetRVA. Every
			// section moved by `delta`, so every relocated
			// pointer's value also gets += delta.
			binary.LittleEndian.PutUint64(out[fileOff:], val+uint64(delta))
		case RelTypeHighLow:
			fileOff, ferr := rvaToFileOffOld(out, l, ranges, e.RVA)
			if ferr != nil {
				return fmt.Errorf("highlow reloc at RVA 0x%x: %w", e.RVA, ferr)
			}
			if int(fileOff)+4 > len(out) {
				return fmt.Errorf("highlow reloc patch past EOF (RVA 0x%x → file 0x%x)", e.RVA, fileOff)
			}
			val := binary.LittleEndian.Uint32(out[fileOff:])
			binary.LittleEndian.PutUint32(out[fileOff:], val+delta)
		default:
			return fmt.Errorf("unsupported reloc type 0x%x at RVA 0x%x", e.Type, e.RVA)
		}
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}

	return out, nil
}

// secRange is a per-section snapshot of (oldVA, oldVS) used by
// ShiftImageVA's reloc-fixup pass to resolve RVAs against the
// pre-shift layout while writing into the post-shift buffer.
type secRange struct{ oldVA, oldVS uint32 }

// rvaToFileOffOld is rvaToFileOff but resolves against an
// explicit OLD-VA snapshot rather than the (already-mutated)
// section table inside `pe`. Used by ShiftImageVA's reloc
// fixup, where the input VAs in the table are the NEW values
// but reloc entries' RVAs are still in the OLD coordinate
// system (the walker reads from `pe` not `out`).
func rvaToFileOffOld(pe []byte, l peLayout, ranges []secRange, rva uint32) (uint32, error) {
	for i, r := range ranges {
		if rva < r.oldVA || rva >= r.oldVA+r.oldVS {
			continue
		}
		hdrOff := l.secTableOff + uint32(i)*PESectionHdrSize
		secRawOff := binary.LittleEndian.Uint32(pe[hdrOff+SecPointerToRawDataOffset:])
		secRawSize := binary.LittleEndian.Uint32(pe[hdrOff+SecSizeOfRawDataOffset:])
		off := secRawOff + (rva - r.oldVA)
		if off >= secRawOff+secRawSize {
			return 0, fmt.Errorf("RVA 0x%x falls in BSS tail of section %d", rva, i)
		}
		return off, nil
	}
	return 0, fmt.Errorf("RVA 0x%x not in any section", rva)
}
