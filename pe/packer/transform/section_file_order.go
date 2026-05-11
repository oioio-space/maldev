package transform

import (
	"encoding/binary"
	"fmt"
	"math/rand"
)

// PermuteSectionFileOrder rearranges the order in which the
// pre-stub section bodies appear in the FILE while leaving every
// section's VirtualAddress, VirtualSize, Characteristics, and
// every absolute pointer in the image untouched. PE/COFF allows
// the file layout of section bodies to be in any order with
// arbitrary FileAlignment-padded gaps; the loader maps each
// section by reading its PointerToRawData / SizeOfRawData fields,
// not by file ordering.
//
// Defeats YARA rules anchored at file offsets ("file offset 0x400
// contains the decryption key bytes") without touching VAs,
// relocations, the DataDirectory, or OEP. The runtime image is
// byte-identical to a vanilla pack — only the file image differs.
//
// Skips sections at indices `>= numSections - skipLast` (typically
// `skipLast=1` to leave the appended packer stub unmoved). Returns
// the input unchanged when there are fewer than 2 permutable
// sections (no permutation possible).
//
// Phase 2-F-3-b of docs/refactor-2026-doc/packer-design.md.
//
// Returns the input unchanged with nil error when the operation
// is a no-op; the input slice is never mutated; a fresh buffer of
// the same length is returned in all paths.
func PermuteSectionFileOrder(pe []byte, rng *rand.Rand, skipLast int) ([]byte, error) {
	l, err := parsePELayout(pe)
	if err != nil {
		return nil, err
	}
	if skipLast < 0 {
		return nil, fmt.Errorf("transform: skipLast %d < 0", skipLast)
	}
	if skipLast > int(l.numSections) {
		return nil, fmt.Errorf("transform: skipLast %d > NumberOfSections %d", skipLast, l.numSections)
	}
	permutable := int(l.numSections) - skipLast
	if permutable < 2 {
		// Nothing to permute.
		out := make([]byte, len(pe))
		copy(out, pe)
		return out, nil
	}
	fileAlign := binary.LittleEndian.Uint32(pe[l.optOff+OptFileAlignOffset:])
	if fileAlign == 0 {
		return nil, fmt.Errorf("transform: FileAlignment is zero")
	}

	// Snapshot per-section file-image extent (PointerToRawData,
	// SizeOfRawData) for the permutable subset. We only move
	// sections with SizeOfRawData > 0 — uninitialised sections
	// (BSS, Phase 2-F-2 separators) have no file backing and
	// stay where they are (which is "nowhere").
	type sec struct {
		hdrIdx     uint16
		oldRawOff  uint32
		oldRawSize uint32
	}
	withData := make([]sec, 0, permutable)
	for i := 0; i < permutable; i++ {
		hdrOff := l.secTableOff + uint32(i)*PESectionHdrSize
		rawOff := binary.LittleEndian.Uint32(pe[hdrOff+SecPointerToRawDataOffset:])
		rawSize := binary.LittleEndian.Uint32(pe[hdrOff+SecSizeOfRawDataOffset:])
		if rawSize == 0 {
			continue
		}
		withData = append(withData, sec{hdrIdx: uint16(i), oldRawOff: rawOff, oldRawSize: rawSize})
	}
	if len(withData) < 2 {
		out := make([]byte, len(pe))
		copy(out, pe)
		return out, nil
	}

	// Find the lowest PointerToRawData in the permutable set —
	// that's our layout cursor's start. Sections to be permuted
	// will repack into the SAME contiguous file range they
	// originally occupied (no file-size change), just in a new
	// order.
	cursor := withData[0].oldRawOff
	for _, s := range withData[1:] {
		if s.oldRawOff < cursor {
			cursor = s.oldRawOff
		}
	}
	// Compute the original total span — the sum of aligned
	// SizeOfRawData across the permutable set. The new layout
	// must fit in the same span so we don't perturb sections
	// not in the permutable set (e.g. the stub).
	var span uint32
	for _, s := range withData {
		span += alignUpU32(s.oldRawSize, fileAlign)
	}

	// Generate a random permutation of withData using the
	// caller-supplied RNG. Reject identity by re-shuffling
	// (avoids "permutation is no-op" when seeded unluckily).
	perm := make([]int, len(withData))
	for i := range perm {
		perm[i] = i
	}
	for attempt := 0; attempt < 8; attempt++ {
		rng.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		identity := true
		for i, p := range perm {
			if p != i {
				identity = false
				break
			}
		}
		if !identity {
			break
		}
	}

	out := make([]byte, len(pe))
	copy(out, pe)

	// Save original section bodies before overwriting their file
	// slots — sections may shift forward AND backward in the new
	// order so a naïve in-place copy would clobber neighbours.
	bodies := make([][]byte, len(withData))
	for i, s := range withData {
		bodies[i] = make([]byte, s.oldRawSize)
		copy(bodies[i], pe[s.oldRawOff:s.oldRawOff+s.oldRawSize])
	}

	// COFF.PointerToSymbolTable usually coincides with the
	// .symtab section's PointerToRawData. When that section
	// moves we must update the COFF pointer or debug/pe and
	// COFF-aware tools choke ("fail to read string table").
	// NumberOfSymbols == 0 still requires a valid string-table
	// header (first 4 bytes = size) at the pointed offset.
	const coffPtrToSymTabOffset = 0x08
	pSymOff := l.coffOff + coffPtrToSymTabOffset
	oldSymPtr := binary.LittleEndian.Uint32(pe[pSymOff:])
	var carrierIdx int = -1
	if oldSymPtr != 0 {
		for i, s := range withData {
			if oldSymPtr >= s.oldRawOff && oldSymPtr < s.oldRawOff+s.oldRawSize {
				carrierIdx = i
				break
			}
		}
	}

	// Zero-fill the original span so any padding bytes between
	// the new section layout don't leak old contents.
	for i := cursor; i < cursor+span; i++ {
		out[i] = 0
	}

	// Re-emit bodies in the new order, updating each section's
	// PointerToRawData header field. Track the new offset of the
	// COFF symbol-table carrier section if any.
	emitOff := cursor
	for _, p := range perm {
		s := withData[p]
		hdrOff := l.secTableOff + uint32(s.hdrIdx)*PESectionHdrSize
		binary.LittleEndian.PutUint32(out[hdrOff+SecPointerToRawDataOffset:], emitOff)
		copy(out[emitOff:emitOff+s.oldRawSize], bodies[p])
		if p == carrierIdx {
			binary.LittleEndian.PutUint32(out[pSymOff:], emitOff+(oldSymPtr-s.oldRawOff))
		}
		emitOff += alignUpU32(s.oldRawSize, fileAlign)
	}
	return out, nil
}
