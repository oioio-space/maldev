package transform

import (
	"fmt"
	"math/rand"
)

// RandomizeExistingSectionNames overwrites every section header's
// 8-byte Name slot with a fresh random ".xxxxx\0\0" identifier.
// Pure header-table mutation: section data, VAs, raw offsets,
// sizes, characteristics, the DataDirectory, and the relocation
// table are all untouched. Windows finds resources, imports,
// exports, relocations etc. via the Optional Header DataDirectory
// (RVA-based), so renaming `.text` → `.xkqwz` doesn't break the
// loader contract.
//
// Phase 2-F-1 of docs/refactor-2026-doc/packer-design.md: defeats
// name-pattern heuristics like "section called .text is RWX —
// suspicious" or YARA rules keyed on a packer's signature section
// names. Composes with [RandomStubSectionName] (Phase 2-A) — the
// stub section is appended *after* this call, so its name is
// controlled separately.
//
// `skipLast` exempts the last `skipLast` section headers from
// renaming — pass 1 to leave a packer-appended stub section
// (controlled separately by [RandomStubSectionName]) untouched.
//
// Names are unique within the same PE (rejection sampling on
// collision). Deterministic given a seeded *rand.Rand.
func RandomizeExistingSectionNames(pe []byte, rng *rand.Rand, skipLast int) error {
	l, err := parsePELayout(pe)
	if err != nil {
		return err
	}
	if skipLast < 0 {
		return fmt.Errorf("transform: skipLast %d < 0", skipLast)
	}
	if skipLast > int(l.numSections) {
		return fmt.Errorf("transform: skipLast %d > NumberOfSections %d", skipLast, l.numSections)
	}
	renameUpTo := uint16(int(l.numSections) - skipLast)
	// PE/COFF max is 96 sections; typical is 4-8. A linear-scan
	// slice beats a map at this size — fewer allocs, better cache.
	used := make([][8]byte, 0, renameUpTo)
	for i := uint16(0); i < renameUpTo; i++ {
		hdrOff := l.secTableOff + uint32(i)*PESectionHdrSize
		var name [8]byte
		// Bounded retry — 26^5 ≈ 11.8M unique names vs at most
		// 96 sections, collision rate ~4e-4. Cap at 4 attempts.
		for attempt := 0; attempt < 4; attempt++ {
			name = RandomStubSectionName(rng)
			collision := false
			for _, u := range used {
				if u == name {
					collision = true
					break
				}
			}
			if !collision {
				break
			}
		}
		used = append(used, name)
		copy(pe[hdrOff:hdrOff+8], name[:])
	}
	return nil
}
