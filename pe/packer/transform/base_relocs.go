package transform

import (
	"encoding/binary"
	"fmt"
)

// PE/COFF base-relocation type codes (a.k.a. IMAGE_REL_BASED_*).
// Only the codes the packer needs are exported; the full set is
// in the PE/COFF specification.
const (
	// RelTypeAbsolute is a padding entry — the loader skips it.
	RelTypeAbsolute uint16 = 0
	// RelTypeHighLow is a 32-bit absolute address. Used by 32-bit
	// PE images and rarely by x64 (we encounter it in /LARGEADDRESSAWARE
	// images that still ship a 32-bit reloc).
	RelTypeHighLow uint16 = 3
	// RelTypeDir64 is a 64-bit absolute address. The dominant
	// type in modern x64 PEs.
	RelTypeDir64 uint16 = 10
)

// dirBaseReloc is the DataDirectory index for the base-relocation
// table (IMAGE_DIRECTORY_ENTRY_BASERELOC). The entry holds an RVA
// + size pointing at a sequence of IMAGE_BASE_RELOCATION blocks.
const dirBaseReloc = 5

// BaseRelocEntry is one decoded relocation: RVA of the patched
// location, the type code, and the index of the entry within
// its containing block (handy for callers that need to repack
// the table later).
type BaseRelocEntry struct {
	BlockVA   uint32 // page RVA the entry's block declares
	BlockOff  uint32 // file offset of the block header (start of the 8-byte header)
	EntryIdx  uint32 // 0-based index of this entry within the block
	EntryOff  uint32 // file offset of this entry's 16-bit record
	RVA       uint32 // BlockVA + (record & 0x0FFF) — the address being patched
	Type      uint16 // RelTypeAbsolute / HighLow / Dir64 / …
}

// WalkBaseRelocs walks the base-relocation directory and invokes
// `cb` once per entry (including padding RelTypeAbsolute entries
// — caller decides whether to filter). Read-only: never mutates
// `pe`. Returns immediately with nil error when the directory is
// empty (image was linked /FIXED or has no relocs).
//
// `cb` returning a non-nil error stops the walk and propagates
// the error.
//
// Phase 2-F-3-a of docs/refactor-2026-doc/packer-design.md —
// foundation helper for section-shift / permutation passes that
// need to enumerate every absolute pointer in the image.
func WalkBaseRelocs(pe []byte, cb func(BaseRelocEntry) error) error {
	l, err := parsePELayout(pe)
	if err != nil {
		return err
	}
	dirOff := l.optOff + OptDataDirsStart + dirBaseReloc*OptDataDirEntrySize
	if int(dirOff)+OptDataDirEntrySize > len(pe) {
		return fmt.Errorf("transform: PE too short for base-reloc DataDirectory")
	}
	dirRVA := binary.LittleEndian.Uint32(pe[dirOff:])
	dirSize := binary.LittleEndian.Uint32(pe[dirOff+4:])
	if dirRVA == 0 || dirSize == 0 {
		return nil
	}

	// Reloc directory addresses are RVAs; the packer's transforms
	// run on the file image where RVA != file offset. Resolve via
	// the section table.
	dirFileOff, err := rvaToFileOff(pe, l, dirRVA)
	if err != nil {
		return fmt.Errorf("transform: base-reloc directory RVA: %w", err)
	}

	block := uint32(0)
	for block < dirSize {
		hdrOff := dirFileOff + block
		if int(hdrOff)+8 > len(pe) {
			return fmt.Errorf("transform: base-reloc block header past EOF")
		}
		pageRVA := binary.LittleEndian.Uint32(pe[hdrOff:])
		blockSize := binary.LittleEndian.Uint32(pe[hdrOff+4:])
		if blockSize < 8 {
			return fmt.Errorf("transform: bogus base-reloc block size %d", blockSize)
		}
		if blockSize > dirSize-block {
			return fmt.Errorf("transform: base-reloc block size %d overruns directory", blockSize)
		}
		entries := (blockSize - 8) / 2
		for i := uint32(0); i < entries; i++ {
			entryOff := hdrOff + 8 + i*2
			rec := binary.LittleEndian.Uint16(pe[entryOff:])
			ent := BaseRelocEntry{
				BlockVA:  pageRVA,
				BlockOff: hdrOff,
				EntryIdx: i,
				EntryOff: entryOff,
				RVA:      pageRVA + uint32(rec&0x0FFF),
				Type:     rec >> 12,
			}
			if cberr := cb(ent); cberr != nil {
				return cberr
			}
		}
		block += blockSize
	}
	return nil
}

// rvaToFileOff resolves an RVA to a file offset by walking the
// section table for the section that contains it. Returns an
// error when the RVA falls outside every section's mapped span.
//
// The packer's transforms operate on the un-mapped file image —
// VAs and file offsets diverge. This helper centralises the
// conversion so every reloc/data-directory consumer agrees.
func rvaToFileOff(pe []byte, l peLayout, rva uint32) (uint32, error) {
	for i := uint16(0); i < l.numSections; i++ {
		hdrOff := l.secTableOff + uint32(i)*PESectionHdrSize
		secVA := binary.LittleEndian.Uint32(pe[hdrOff+SecVirtualAddressOffset:])
		secVS := binary.LittleEndian.Uint32(pe[hdrOff+SecVirtualSizeOffset:])
		secRawOff := binary.LittleEndian.Uint32(pe[hdrOff+SecPointerToRawDataOffset:])
		secRawSize := binary.LittleEndian.Uint32(pe[hdrOff+SecSizeOfRawDataOffset:])
		// VirtualSize may be larger than SizeOfRawData (uninitialised
		// trailing bytes); accept the RVA as long as it falls in the
		// virtual span AND the file image actually has bytes there.
		if rva < secVA || rva >= secVA+secVS {
			continue
		}
		off := secRawOff + (rva - secVA)
		if off >= secRawOff+secRawSize {
			return 0, fmt.Errorf("RVA 0x%x falls in BSS tail of section %d", rva, i)
		}
		return off, nil
	}
	return 0, fmt.Errorf("RVA 0x%x not in any section", rva)
}

