package transform

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// OptImageBase64Offset is the file offset of the PE32+ Optional
// Header's ImageBase field (uint64). The value is the loader's
// PREFERRED load address; under ASLR the loader is free to map
// the image elsewhere and use the .reloc table to fix up
// absolute pointers.
const OptImageBase64Offset = 0x18

// OptDllCharacteristicsOffset is the file offset of the
// DllCharacteristics field inside the PE32+ Optional Header.
const OptDllCharacteristicsOffset = 0x46

// DllCharDynamicBase is IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE.
// The bit signals "this image opts in to ASLR". Without it, the
// loader tries to map at exactly ImageBase and fails when that
// region is occupied — so randomising ImageBase requires the
// bit to be set.
const DllCharDynamicBase uint16 = 0x0040

// RandomImageBaseAlignment is the alignment Windows requires for
// ImageBase (64 KiB per PE/COFF spec — multiples of the
// allocation granularity). Random draws are snapped to this.
const RandomImageBaseAlignment uint64 = 0x10000

// RandomImageBase64 returns a plausible PE32+ ImageBase drawn
// from the canonical user-mode range for native EXEs:
// `[0x140000000, 0x7FF000000000)` snapped to
// [RandomImageBaseAlignment]. Range chosen to stay inside the
// 47-bit user-mode VA space the Windows loader maps EXEs into,
// while avoiding the bottom 5 GiB where Win10 prefers system
// allocations.
//
// Operators wanting deterministic output across packs pass a
// seeded *rand.Rand.
func RandomImageBase64(rng *rand.Rand) uint64 {
	const (
		minBase uint64 = 0x140000000
		maxBase uint64 = 0x7FF000000000
	)
	span := (maxBase - minBase) / RandomImageBaseAlignment
	return minBase + uint64(rng.Int63n(int64(span)))*RandomImageBaseAlignment
}

// PatchPEImageBase overwrites the PE32+ Optional Header's
// ImageBase (uint64) with `base`. Pure byte mutation — under
// ASLR the loader picks the actual load address regardless of
// this value, so the only observable effect is a different
// preferred-base byte sequence in the file image. Defeats
// heuristics on canonical preferred-base values like the Go
// linker's 0x140000000 default.
//
// Phase 2-F-3-c (lite) of docs/refactor-2026-doc/packer-design.md
// — pragmatic alternative to the full whole-image VA shift
// (which needs per-directory internal-RVA walkers we haven't
// shipped yet).
//
// Returns an error when `pe` is too short to contain the
// Optional Header up to and including ImageBase, or when the
// image lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE — without
// ASLR opt-in the loader tries to map at exactly the new (random)
// ImageBase, fails to find that region free, and aborts before
// applying the .reloc table.
func PatchPEImageBase(pe []byte, base uint64) error {
	l, err := parsePELayout(pe)
	if err != nil {
		return err
	}
	if int(l.optOff)+OptDllCharacteristicsOffset+2 > len(pe) {
		return fmt.Errorf("transform: PE too short for Optional Header DllCharacteristics")
	}
	dllChar := binary.LittleEndian.Uint16(pe[l.optOff+OptDllCharacteristicsOffset:])
	if dllChar&DllCharDynamicBase == 0 {
		return fmt.Errorf("transform: PE lacks IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE — random ImageBase would prevent loading")
	}
	if int(l.optOff)+OptImageBase64Offset+8 > len(pe) {
		return fmt.Errorf("transform: PE too short for Optional Header ImageBase")
	}
	// CRITICAL: writing a new preferred ImageBase without
	// adjusting the in-file absolute pointer values would break
	// the loader's rebase math. The loader computes
	// `actual_addr = file_value + (actual_base - preferred_base)`.
	// The file values were generated against `oldBase`, so they
	// encode `oldBase + RVA`. If we change preferred to `base`,
	// the loader's delta becomes `(actual - base)` — applied to
	// `oldBase + RVA` it yields `actual + (oldBase - base) + RVA`,
	// off by `(oldBase - base)` from the right answer.
	//
	// Fix: walk relocs and add `(base - oldBase)` to every DIR64
	// / HIGHLOW patch target so post-rebase values land where
	// the loader expects.
	oldBase := binary.LittleEndian.Uint64(pe[l.optOff+OptImageBase64Offset:])
	delta := base - oldBase
	if delta != 0 {
		if walkErr := WalkBaseRelocs(pe, func(e BaseRelocEntry) error {
			fileOff, ferr := rvaToFileOff(pe, l, e.RVA)
			if ferr != nil {
				return fmt.Errorf("imagebase reloc at RVA 0x%x: %w", e.RVA, ferr)
			}
			switch e.Type {
			case RelTypeAbsolute:
				return nil
			case RelTypeDir64:
				if int(fileOff)+8 > len(pe) {
					return fmt.Errorf("dir64 patch past EOF")
				}
				v := binary.LittleEndian.Uint64(pe[fileOff:])
				binary.LittleEndian.PutUint64(pe[fileOff:], v+delta)
			case RelTypeHighLow:
				if int(fileOff)+4 > len(pe) {
					return fmt.Errorf("highlow patch past EOF")
				}
				v := binary.LittleEndian.Uint32(pe[fileOff:])
				binary.LittleEndian.PutUint32(pe[fileOff:], v+uint32(delta))
			default:
				return fmt.Errorf("unsupported reloc type 0x%x at RVA 0x%x", e.Type, e.RVA)
			}
			return nil
		}); walkErr != nil {
			return fmt.Errorf("transform: imagebase reloc walk: %w", walkErr)
		}
	}
	binary.LittleEndian.PutUint64(pe[l.optOff+OptImageBase64Offset:], base)
	return nil
}
