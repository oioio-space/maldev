package transform

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// Optional Header LinkerVersion field offsets (PE32+, relative to
// the start of the Optional Header at coffOff + 20).
const (
	// OptMajorLinkerVersionOffset is the file offset of the
	// MajorLinkerVersion byte inside the Optional Header.
	OptMajorLinkerVersionOffset = 0x02
	// OptMinorLinkerVersionOffset is the file offset of the
	// MinorLinkerVersion byte inside the Optional Header.
	OptMinorLinkerVersionOffset = 0x03
)

// PatchPELinkerVersion overwrites the Optional Header's
// MajorLinkerVersion + MinorLinkerVersion bytes in `pe`. Pure
// byte mutation — the loader doesn't read these fields, they're
// descriptive only (operator tooling like dumpbin / pe-tree
// surfaces them as "linked with vN.M").
//
// Phase 2-C of docs/refactor-2026-doc/packer-design.md: defeats
// threat-intel pivots that cluster samples by linker version
// ("all samples linked with VS2017 14.16"). Operators randomise
// per-pack via [RandomLinkerVersion].
//
// Returns an error when `pe` is too short to contain the Optional
// Header.
func PatchPELinkerVersion(pe []byte, major, minor uint8) error {
	if len(pe) < int(PEELfanewOffset)+4 {
		return fmt.Errorf("transform: PE too short for e_lfanew")
	}
	peOff := binary.LittleEndian.Uint32(pe[PEELfanewOffset : PEELfanewOffset+4])
	optOff := peOff + PESignatureSize + PECOFFHdrSize
	if int(optOff)+4 > len(pe) {
		return fmt.Errorf("transform: PE too short for Optional Header")
	}
	pe[optOff+OptMajorLinkerVersionOffset] = major
	pe[optOff+OptMinorLinkerVersionOffset] = minor
	return nil
}

// RandomLinkerVersion returns a (major, minor) pair drawn from
// the plausible MSVC range (major ∈ [12, 15], minor ∈ [0, 99]).
// Mirrors what `link.exe` from VS2013-2022 stamps:
//
//	12.x  → Visual Studio 2013
//	14.0  → Visual Studio 2015
//	14.1x → Visual Studio 2017
//	14.2x → Visual Studio 2019
//	14.3x → Visual Studio 2022
//	15.x  → forward-compat headroom
//
// Operators wanting deterministic output across packs pass a
// seeded *rand.Rand.
func RandomLinkerVersion(rng *rand.Rand) (major, minor uint8) {
	// Major: 12..15 inclusive (4 values).
	major = uint8(12 + rng.Intn(4))
	// Minor: 0..99 — any plausible point release.
	minor = uint8(rng.Intn(100))
	return major, minor
}
