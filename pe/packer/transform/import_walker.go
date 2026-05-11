package transform

import (
	"encoding/binary"
	"fmt"
)

// dirImport is the DataDirectory index for the import table
// (IMAGE_DIRECTORY_ENTRY_IMPORT). The entry holds an RVA + size
// pointing at an array of IMAGE_IMPORT_DESCRIPTOR (20 bytes
// each), terminated by a zero descriptor.
const dirImport = 1

// IMAGE_IMPORT_DESCRIPTOR field offsets (PE/COFF spec §6.4.4).
const (
	impDescOriginalFirstThunkOff = 0x00 // RVA → ILT (Import Lookup Table)
	impDescNameOff               = 0x0C // RVA → DLL name (null-terminated)
	impDescFirstThunkOff         = 0x10 // RVA → IAT (Import Address Table)
	impDescSize                  = 0x14 // 20 bytes per descriptor
)

// imageOrdinalFlag64 is IMAGE_ORDINAL_FLAG64 — a thunk whose top
// bit is set encodes an ordinal import (low 16 bits = ordinal).
// Top bit clear means the low 31 bits hold an RVA pointing at an
// IMAGE_IMPORT_BY_NAME { uint16 Hint; char Name[]; }.
const imageOrdinalFlag64 uint64 = 0x8000000000000000

// WalkImportDirectoryRVAs walks the import directory and yields
// every internal RVA field by its file offset. Callers patch the
// uint32 at each yielded offset (e.g. add a delta to relocate the
// directory under [ShiftImageVA]).
//
// Yielded fields per non-terminating IMAGE_IMPORT_DESCRIPTOR:
//
//	OriginalFirstThunk RVA  — descriptor offset +0x00 (uint32)
//	Name RVA                — descriptor offset +0x0C (uint32)
//	FirstThunk RVA          — descriptor offset +0x10 (uint32)
//
// Then for every "by-name" thunk in BOTH the ILT (pointed at by
// OriginalFirstThunk) and the IAT (pointed at by FirstThunk):
//
//	low-32-bits of the uint64 thunk — the RVA portion of an
//	IMAGE_IMPORT_BY_NAME pointer. The high 4 bytes (which carry
//	the IMAGE_ORDINAL_FLAG64 bit) are NOT yielded; callers
//	patching the low 4 bytes leave the type discriminator alone.
//
// "By-ordinal" thunks (top bit set) are skipped — they encode
// numeric ordinals, not RVAs.
//
// Both ILT and IAT are walked because some linkers emit only the
// FirstThunk (no separate ILT), in which case the loader reads
// the IAT for resolution metadata before overwriting it. Patching
// both keeps both code paths happy.
//
// Read-only: never mutates `pe`. Returns nil when the directory
// is empty (image with no imports). Callback returning a non-nil
// error stops the walk and propagates.
//
// Phase 2-F-3-c-2 of docs/refactor-2026-doc/packer-2f3c-walker-suite-plan.md.
func WalkImportDirectoryRVAs(pe []byte, cb func(rvaFileOff uint32) error) error {
	l, err := parsePELayout(pe)
	if err != nil {
		return err
	}
	dirEntryOff := l.optOff + OptDataDirsStart + dirImport*OptDataDirEntrySize
	if int(dirEntryOff)+OptDataDirEntrySize > len(pe) {
		return fmt.Errorf("transform: PE too short for import DataDirectory")
	}
	dirRVA := binary.LittleEndian.Uint32(pe[dirEntryOff:])
	dirSize := binary.LittleEndian.Uint32(pe[dirEntryOff+4:])
	if dirRVA == 0 || dirSize == 0 {
		return nil
	}
	dirFileOff, err := rvaToFileOff(pe, l, dirRVA)
	if err != nil {
		return fmt.Errorf("transform: import directory RVA: %w", err)
	}

	// Walk descriptors until the zero terminator OR until we exit
	// the directory's declared size — whichever comes first. Some
	// linkers omit the explicit zero terminator and rely on the
	// declared size; respect both.
	for desc := uint32(0); desc+impDescSize <= dirSize; desc += impDescSize {
		descOff := dirFileOff + desc
		if int(descOff)+impDescSize > len(pe) {
			return fmt.Errorf("transform: import descriptor past EOF (offset 0x%x)", descOff)
		}
		oft := binary.LittleEndian.Uint32(pe[descOff+impDescOriginalFirstThunkOff:])
		nameRVA := binary.LittleEndian.Uint32(pe[descOff+impDescNameOff:])
		ft := binary.LittleEndian.Uint32(pe[descOff+impDescFirstThunkOff:])
		// Zero descriptor = end of array.
		if oft == 0 && nameRVA == 0 && ft == 0 {
			break
		}
		// Yield the descriptor's three RVA fields. OFT and Name
		// must be non-zero for a real import; FT is sometimes 0
		// (rare but valid for delay-import-style entries). Skip
		// zero fields so the caller's "value+delta" doesn't turn
		// a sentinel zero into a non-zero garbage RVA.
		if oft != 0 {
			if cberr := cb(descOff + impDescOriginalFirstThunkOff); cberr != nil {
				return cberr
			}
		}
		if nameRVA != 0 {
			if cberr := cb(descOff + impDescNameOff); cberr != nil {
				return cberr
			}
		}
		if ft != 0 {
			if cberr := cb(descOff + impDescFirstThunkOff); cberr != nil {
				return cberr
			}
		}

		// Walk the ILT (OFT) and the IAT (FT). Both are uint64
		// arrays terminated by a zero entry.
		for _, thunkArrayRVA := range []uint32{oft, ft} {
			if thunkArrayRVA == 0 {
				continue
			}
			if walkErr := walkThunkArrayBynameRVAs(pe, l, thunkArrayRVA, cb); walkErr != nil {
				return walkErr
			}
		}
	}
	return nil
}

// walkThunkArrayBynameRVAs yields the file offset of the LOW 4
// bytes of every by-name thunk in the array starting at
// `arrayRVA`. By-ordinal thunks (top bit set) are skipped.
// Walks until a zero thunk terminator is encountered.
func walkThunkArrayBynameRVAs(pe []byte, l peLayout, arrayRVA uint32, cb func(uint32) error) error {
	off, err := rvaToFileOff(pe, l, arrayRVA)
	if err != nil {
		return fmt.Errorf("transform: thunk array RVA 0x%x: %w", arrayRVA, err)
	}
	for {
		if int(off)+8 > len(pe) {
			return fmt.Errorf("transform: thunk past EOF (file 0x%x)", off)
		}
		thunk := binary.LittleEndian.Uint64(pe[off:])
		if thunk == 0 {
			return nil
		}
		if thunk&imageOrdinalFlag64 == 0 {
			// By-name: low 32 bits are an RVA. Yield the
			// file offset of those low 4 bytes.
			if cberr := cb(off); cberr != nil {
				return cberr
			}
		}
		off += 8
	}
}
