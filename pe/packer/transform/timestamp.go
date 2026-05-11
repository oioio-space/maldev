package transform

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// COFFTimeDateStampOffset is the file offset of the TimeDateStamp
// field inside the COFF File Header (per Microsoft PE/COFF
// Specification Rev 12.0). The field is a 4-byte little-endian
// uint32 holding the seconds since 1970-01-01 00:00:00 UTC the
// linker stamped at build time.
const COFFTimeDateStampOffset = 0x04

// PatchPETimeDateStamp overwrites the COFF File Header's
// TimeDateStamp in `pe` with `ts`. Pure byte mutation, no
// section-table or RVA recomputation needed — the kernel loader
// doesn't read this field.
//
// Phase 2-B of docs/refactor-2026-doc/packer-design.md: defeats
// temporal clustering by threat-intel pivots that group samples
// by linker timestamp. Operators randomise per-pack via
// [RandomTimeDateStamp].
//
// Returns an error when `pe` is too short to contain the COFF
// header (e.g. truncated input or a non-PE byte buffer).
func PatchPETimeDateStamp(pe []byte, ts uint32) error {
	if len(pe) < int(PEELfanewOffset)+4 {
		return fmt.Errorf("transform: PE too short for e_lfanew")
	}
	peOff := binary.LittleEndian.Uint32(pe[PEELfanewOffset : PEELfanewOffset+4])
	tsOff := peOff + PESignatureSize + COFFTimeDateStampOffset
	if int(tsOff)+4 > len(pe) {
		return fmt.Errorf("transform: PE too short for COFF TimeDateStamp")
	}
	binary.LittleEndian.PutUint32(pe[tsOff:tsOff+4], ts)
	return nil
}

// RandomTimeDateStamp returns a uint32 epoch-second timestamp in
// the plausible "recently linked" window: between `now - 5 years`
// and `now`. Operators wanting deterministic output across packs
// pass a seeded *rand.Rand; uniqueness across packs comes from
// fresh-seeded calls.
//
// Range bounds picked to match what threat-intel hunters typically
// expect — too-old timestamps stand out as "the linker was lying"
// and become their own pivot signal.
func RandomTimeDateStamp(rng *rand.Rand, nowEpoch uint32) uint32 {
	// 5 years ≈ 5 × 365 × 24 × 3600 = 157_680_000 seconds.
	const fiveYears uint32 = 157_680_000
	if nowEpoch <= fiveYears {
		// Edge case: nowEpoch suspiciously small (test fixture or
		// pre-epoch). Return any value in [0, nowEpoch].
		if nowEpoch == 0 {
			return uint32(rng.Int31())
		}
		return uint32(rng.Int63n(int64(nowEpoch)))
	}
	delta := uint32(rng.Int63n(int64(fiveYears)))
	return nowEpoch - delta
}
