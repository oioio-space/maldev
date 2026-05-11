package transform

import (
	"encoding/binary"
	"math/rand"
)

// Optional Header ImageVersion field offsets (PE32+, relative to
// the start of the Optional Header at coffOff + 20). MajorImageVersion
// and MinorImageVersion sit at +0x2C / +0x2E in the PE32+ Windows-
// Specific Fields block (per Microsoft PE/COFF Spec Rev 12.0).
const (
	// OptMajorImageVersionOffset is the file offset of the
	// MajorImageVersion uint16 inside the Optional Header.
	OptMajorImageVersionOffset = 0x2C
	// OptMinorImageVersionOffset is the file offset of the
	// MinorImageVersion uint16 inside the Optional Header.
	OptMinorImageVersionOffset = 0x2E
)

// PatchPEImageVersion overwrites the Optional Header's
// MajorImageVersion + MinorImageVersion fields in `pe`. Pure
// byte mutation — the kernel loader doesn't read these fields,
// they're operator-controlled descriptive metadata (set via
// `link /VERSION:major.minor`).
//
// Phase 2-D of docs/refactor-2026-doc/packer-design.md: defeats
// threat-intel pivots that cluster samples by the per-binary
// version stamp.
//
// Returns an error when `pe` is too short to contain the
// Optional Header up to and including the ImageVersion fields.
func PatchPEImageVersion(pe []byte, major, minor uint16) error {
	l, err := parsePELayout(pe)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint16(pe[l.optOff+OptMajorImageVersionOffset:], major)
	binary.LittleEndian.PutUint16(pe[l.optOff+OptMinorImageVersionOffset:], minor)
	return nil
}

// RandomImageVersion returns a (major, minor) pair drawn from
// the plausible "small in-house project" range (major ∈ [0, 9],
// minor ∈ [0, 99]). Real binaries vary wildly here — Microsoft
// uses 10.0 for Windows components, MSVC defaults to 0.0 when
// the linker isn't told otherwise, vendor apps typically run
// 1.x to 9.x. The chosen range covers the defaults + most
// in-house projects without straying into the "10.x" Microsoft-
// component zone (which would itself be a pivot).
func RandomImageVersion(rng *rand.Rand) (major, minor uint16) {
	major = uint16(rng.Intn(10))
	minor = uint16(rng.Intn(100))
	return major, minor
}
