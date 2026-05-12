package transform

import (
	"encoding/binary"
	"fmt"
)

// dirResource is the DataDirectory index for the resource tree
// (IMAGE_DIRECTORY_ENTRY_RESOURCE).
const dirResource = 2

// PE resource directory layout (Microsoft PE/COFF Specification):
//
//	IMAGE_RESOURCE_DIRECTORY (16 B):
//	  +0x0  Characteristics       uint32
//	  +0x4  TimeDateStamp         uint32
//	  +0x8  MajorVersion          uint16
//	  +0xA  MinorVersion          uint16
//	  +0xC  NumberOfNamedEntries  uint16
//	  +0xE  NumberOfIdEntries     uint16
//	  followed by (NumberOfNamedEntries + NumberOfIdEntries) ×
//	  IMAGE_RESOURCE_DIRECTORY_ENTRY (8 B each):
//	    +0x0  NameOrID    uint32 (high bit set → name offset, clear → ID)
//	    +0x4  OffsetToData uint32 (high bit set → subdirectory, clear → leaf)
//	  Both offsets are RELATIVE TO THE RESOURCE DIRECTORY BASE
//	  (NOT RVAs) — they don't need patching under a VA shift.
//
//	IMAGE_RESOURCE_DATA_ENTRY (16 B, leaf only):
//	  +0x0  OffsetToData  uint32 — **RVA** (this is what needs patching)
//	  +0x4  Size          uint32
//	  +0x8  CodePage      uint32
//	  +0xC  Reserved      uint32
const (
	resourceDirectorySize           = 16
	resourceDirectoryEntrySize      = 8
	resourceDataEntrySize           = 16
	resourceSubdirHighBit           = 0x80000000
	resourceMaxRecursionDepth       = 8 // PE files are 3-deep (Type→Name→Lang); cap defensively
	resourceDataEntryOffsetToDataAt = 0
)

// WalkResourceDirectoryRVAs walks the resource directory tree
// and yields the file offset of every leaf
// `IMAGE_RESOURCE_DATA_ENTRY.OffsetToData` field. Callers patch
// the uint32 at each yielded offset (e.g. add a delta to
// relocate the resource tree under [ShiftImageVA]).
//
// The intermediate directory entries' Name + OffsetToData
// fields are NOT yielded — they're offsets RELATIVE to the
// resource directory base, so a VA shift doesn't move them.
//
// Read-only: never mutates `pe`. Returns nil when the directory
// is empty (image with no resources). Callback returning a
// non-nil error stops the walk and propagates.
//
// Recursion depth capped at [resourceMaxRecursionDepth] = 8 to
// guard against pathological / malicious resource trees;
// real-world PEs are 3 levels deep (Type → Name → Language →
// Data leaf).
//
// Phase 2-F-3-c-3 of docs/refactor-2026-doc/packer-2f3c-walker-suite-plan.md.
func WalkResourceDirectoryRVAs(pe []byte, cb func(rvaFileOff uint32) error) error {
	l, err := parsePELayout(pe)
	if err != nil {
		return err
	}
	dirEntryOff := l.optOff + OptDataDirsStart + dirResource*OptDataDirEntrySize
	if int(dirEntryOff)+OptDataDirEntrySize > len(pe) {
		return fmt.Errorf("transform: PE too short for resource DataDirectory")
	}
	dirRVA := binary.LittleEndian.Uint32(pe[dirEntryOff:])
	dirSize := binary.LittleEndian.Uint32(pe[dirEntryOff+4:])
	if dirRVA == 0 || dirSize == 0 {
		return nil
	}
	rootFileOff, err := rvaToFileOff(pe, l, dirRVA)
	if err != nil {
		return fmt.Errorf("transform: resource directory RVA: %w", err)
	}
	return walkResourceSubdir(pe, l, rootFileOff, rootFileOff, dirSize, 0, cb)
}

// walkResourceSubdir recursively descends the resource tree
// starting at file offset `subdirOff`. `rootOff` is the file
// offset of the resource directory's root — entry offsets are
// relative to it. `dirSize` bounds reads inside the directory.
func walkResourceSubdir(
	pe []byte,
	l peLayout,
	subdirOff, rootOff, dirSize uint32,
	depth int,
	cb func(uint32) error,
) error {
	if depth >= resourceMaxRecursionDepth {
		return fmt.Errorf("transform: resource tree depth %d exceeds cap %d (malformed PE?)",
			depth, resourceMaxRecursionDepth)
	}
	if int(subdirOff)+resourceDirectorySize > len(pe) {
		return fmt.Errorf("transform: resource subdirectory header past EOF (file 0x%x)", subdirOff)
	}
	if subdirOff < rootOff || subdirOff >= rootOff+dirSize {
		return fmt.Errorf("transform: resource subdirectory 0x%x outside directory range [0x%x..0x%x)",
			subdirOff, rootOff, rootOff+dirSize)
	}
	namedCount := binary.LittleEndian.Uint16(pe[subdirOff+0x0C:])
	idCount := binary.LittleEndian.Uint16(pe[subdirOff+0x0E:])
	totalEntries := uint32(namedCount) + uint32(idCount)

	entriesStart := subdirOff + resourceDirectorySize
	for i := uint32(0); i < totalEntries; i++ {
		entOff := entriesStart + i*resourceDirectoryEntrySize
		if int(entOff)+resourceDirectoryEntrySize > len(pe) {
			return fmt.Errorf("transform: resource entry %d past EOF (file 0x%x)", i, entOff)
		}
		offsetField := binary.LittleEndian.Uint32(pe[entOff+4:])
		relOff := offsetField & 0x7FFFFFFF // strip high bit (subdir flag)
		targetOff := rootOff + relOff
		if offsetField&resourceSubdirHighBit != 0 {
			// Subdirectory — recurse.
			if err := walkResourceSubdir(pe, l, targetOff, rootOff, dirSize, depth+1, cb); err != nil {
				return err
			}
			continue
		}
		// Leaf: targetOff points at IMAGE_RESOURCE_DATA_ENTRY.
		if int(targetOff)+resourceDataEntrySize > len(pe) {
			return fmt.Errorf("transform: resource data entry past EOF (file 0x%x)", targetOff)
		}
		// Yield the file offset of OffsetToData (the RVA we need
		// to patch).
		if cberr := cb(targetOff + resourceDataEntryOffsetToDataAt); cberr != nil {
			return cberr
		}
	}
	return nil
}
