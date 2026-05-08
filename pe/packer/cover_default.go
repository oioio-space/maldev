package packer

import (
	"fmt"
	"math/rand"
)

// DefaultCoverOptions returns a 3-section CoverOptions tuned for
// general-purpose anti-static-analysis cover. Seed controls the
// (deterministic) name + size + fill choice — operators pass time-
// or PID-derived seeds in production for per-build variance.
//
// The defaults aim at a "looks like a normal compiled binary"
// histogram: one high-entropy section (~8 KiB, named after a
// common PE/ELF resource section), one machine-code-shaped
// section (~4 KiB, JunkFillPattern), one zero-padding section
// (~16 KiB, JunkFillZero). Total static surface increase ~28 KiB
// — small enough not to bloat the binary noticeably, large
// enough to defeat fingerprints that match on exact section
// counts and offsets.
//
// Section names cycle through a pool of legitimate-looking
// candidates: ".rsrc", ".rdata2", ".pdata", ".tls", ".reloc2".
// Names are PE-specific; AddCoverELF ignores the Name field.
func DefaultCoverOptions(seed int64) CoverOptions {
	r := rand.New(rand.NewSource(seed))
	pool := []string{".rsrc", ".rdata2", ".pdata", ".tls", ".reloc2", ".CRT"}
	pick := func() string { return pool[r.Intn(len(pool))] }
	return CoverOptions{
		JunkSections: []JunkSection{
			{Name: pick(), Size: uint32(0x1000 + r.Intn(0x1000)), Fill: JunkFillRandom},
			{Name: pick(), Size: uint32(0x800 + r.Intn(0x800)), Fill: JunkFillPattern},
			{Name: pick(), Size: uint32(0x2000 + r.Intn(0x2000)), Fill: JunkFillZero},
		},
		// DefaultFakeImports uses real Windows 10 1809+ exports so
		// the kernel resolves them cleanly on all supported targets.
		FakeImports: DefaultFakeImports,
	}
}

// ApplyDefaultCover auto-detects whether input is a PE32+ or
// ELF64 and applies the [DefaultCoverOptions] cover layer via
// the matching [AddCoverPE] / [AddCoverELF] entry point.
//
// Convenience wrapper for the common chain:
//
//	packed, _, _ := packer.PackBinary(payload, opts)
//	covered, _   := packer.ApplyDefaultCover(packed, time.Now().UnixNano())
//
// Returns ErrCoverInvalidOptions when the input is neither a PE
// nor an ELF; underlying ELF-specific errors
// (ErrCoverSectionTableFull on Go static-PIE) propagate
// unchanged so operators can decide whether to bail or skip
// cover for that target.
func ApplyDefaultCover(input []byte, seed int64) ([]byte, error) {
	opts := DefaultCoverOptions(seed)
	switch {
	case bytesAreLikelyPE(input):
		return AddCoverPE(input, opts)
	case bytesAreLikelyELF(input):
		return AddCoverELF(input, opts)
	default:
		return nil, fmt.Errorf("%w: input is neither PE32+ nor ELF64", ErrCoverInvalidOptions)
	}
}
