package packer

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// elfPTPhdr is PT_PHDR — the segment that describes the PHT itself.
// Defined in ELF spec § 5.5: "If present, it must precede any
// loadable segment entry." We update it when relocating the PHT so
// it continues to describe the new PHT location.
const elfPTPhdr uint32 = 6

// relocateAndCoverELF is the fallback path for AddCoverELF when the
// input ELF lacks PHT slack (i.e., newTableEnd > firstPTLoadFileOff).
// Go static-PIE binaries always hit this: their first PT_LOAD starts
// at file offset 0, covering both the Ehdr and the existing PHT.
//
// Strategy (ELF spec §§ 2.6, 5.5 + Linux binfmt_elf.c):
//
//  1. Append the new, extended PHT at file-end, page-aligned. The
//     old PHT bytes are left in place; the kernel uses e_phoff, so
//     the stale copy is invisible at load time.
//
//  2. Wrap the relocated PHT in a new R-only PT_LOAD so the kernel
//     maps it (required — the kernel only maps PT_LOAD segments).
//
//  3. Preserve AT_PHDR: the kernel computes
//     AT_PHDR = first_PT_LOAD.vaddr + e_phoff (binfmt_elf.c).
//     Choosing new_e_phoff = coverPhtVAddr − firstLoadVAddr makes
//     AT_PHDR = firstLoadVAddr + (coverPhtVAddr − firstLoadVAddr)
//            = coverPhtVAddr,
//     which lands inside the new PT_LOAD's mapping. ✓
//
//  4. ELF spec invariants:
//     a) PT_PHDR (if present) must be index 0 (§ 5.5).
//     b) PT_LOAD entries must be sorted ascending by p_vaddr (§ 2.6).
//        The new PT_LOAD-for-PHT and cover PT_LOADs all sit above all
//        existing PT_LOADs, so appending them preserves the order.
//     c) vaddr ≡ offset (mod page_size) for PT_LOAD mappings.
//
// Pre-conditions (caller-checked, not re-validated here):
//   - input is a valid ELF64 LE with at least one PT_LOAD.
//   - opts.JunkSections is non-empty.
//   - phentsize == transform.ElfPhdrSize.
func relocateAndCoverELF(
	input []byte,
	opts CoverOptions,
	phoff uint64,
	phentsize uint16,
	phnum uint16,
	maxVEnd, maxFEnd uint64,
) ([]byte, error) {
	// 1. Compute the new PHT size.
	//    Entries = original + 1 (covering PT_LOAD for relocated PHT)
	//            + len(JunkSections) cover PT_LOADs.
	newPhnum := uint16(int(phnum) + 1 + len(opts.JunkSections))
	newPhtSize := uint64(newPhnum) * uint64(phentsize)

	// 2. Choose the file offset F and vaddr V for the new PHT together.
	//
	//    The kernel reads phdrs from FILE offset e_phoff, so e_phoff
	//    must equal F. AT_PHDR = firstLoadVAddr + e_phoff = firstLoadVAddr + F,
	//    which must land inside the new PT_LOAD's mapped range [V, V+size).
	//    The simplest satisfying assignment is V = firstLoadVAddr + F.
	//
	//    V must also be ≥ all existing PT_LOAD vaddrs (ELF § 2.6 ordering),
	//    so V ≥ page_align(maxVEnd) ⟹ F ≥ page_align(maxVEnd) − firstLoadVAddr.
	//
	//    We therefore take F = max(page_align(maxFEnd), page_align(maxVEnd) − firstLoadVAddr),
	//    then align F to a page boundary one more time to ensure p_offset alignment.
	firstLoadVAddr := firstPTLoadVAddr(input, phoff, phentsize, phnum)
	minFFromVAddr := transform.AlignUpU64(maxVEnd, transform.ElfPageSize) - firstLoadVAddr
	minFFromFile := transform.AlignUpU64(maxFEnd, transform.ElfPageSize)
	newPhtFileOff := minFFromFile
	if minFFromVAddr > newPhtFileOff {
		newPhtFileOff = minFFromVAddr
	}
	newPhtFileOff = transform.AlignUpU64(newPhtFileOff, transform.ElfPageSize)

	// V = firstLoadVAddr + F — satisfies AT_PHDR and page-alignment.
	coverPhtVAddr := firstLoadVAddr + newPhtFileOff

	// new_e_phoff == F (the kernel reads phdrs from file at e_phoff).
	newEphoff := newPhtFileOff

	// 3. Plan cover junk sections (same layout math as the in-place
	//    path in AddCoverELF, but starting above the PHT PT_LOAD).
	type planned struct {
		fileOff uint64
		vaddr   uint64
		size    uint64
		fill    JunkFill
	}
	coverPlans := make([]planned, len(opts.JunkSections))
	vCursor := coverPhtVAddr + transform.AlignUpU64(newPhtSize, transform.ElfPageSize)
	fCursor := newPhtFileOff + transform.AlignUpU64(newPhtSize, transform.ElfPageSize)
	for i, js := range opts.JunkSections {
		paged := transform.AlignUpU64(uint64(js.Size), transform.ElfPageSize)
		coverPlans[i] = planned{
			fileOff: fCursor,
			vaddr:   vCursor,
			size:    uint64(js.Size),
			fill:    js.Fill,
		}
		vCursor += paged
		fCursor += paged
	}

	// 4. Allocate output buffer: old file data + new PHT + cover bodies.
	totalSize := fCursor
	if uint64(len(input)) > totalSize {
		totalSize = uint64(len(input))
	}
	out := make([]byte, totalSize)
	copy(out, input)

	// 5. Build the extended PHT in-buffer at newPhtFileOff.
	//    Copy all original phdr entries verbatim, then fix up the
	//    PT_PHDR entry (if present) and append the new entries.
	existingPht := input[phoff : phoff+uint64(phnum)*uint64(phentsize)]
	copy(out[newPhtFileOff:], existingPht)

	// Walk the copied phdrs: find PT_PHDR (if any) and rewrite it.
	// ELF spec § 5.5: PT_PHDR must be the first phdr entry.
	for i := uint16(0); i < phnum; i++ {
		entryOff := newPhtFileOff + uint64(i)*uint64(phentsize)
		ptype := binary.LittleEndian.Uint32(out[entryOff+transform.ElfPhdrTypeOffset : entryOff+transform.ElfPhdrTypeOffset+4])
		if ptype != elfPTPhdr {
			continue
		}
		// Rewrite PT_PHDR to describe the new PHT location.
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrOffsetOffset:entryOff+transform.ElfPhdrOffsetOffset+8], newPhtFileOff)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrVAddrOffset:entryOff+transform.ElfPhdrVAddrOffset+8], coverPhtVAddr)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrPAddrOffset:entryOff+transform.ElfPhdrPAddrOffset+8], coverPhtVAddr)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrFileSzOffset:entryOff+transform.ElfPhdrFileSzOffset+8], newPhtSize)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrMemSzOffset:entryOff+transform.ElfPhdrMemSzOffset+8], newPhtSize)
		break
	}

	// 6. Append PT_LOAD covering the relocated PHT (index phnum in the
	//    new table). Must be in vaddr-ascending order — coverPhtVAddr
	//    is above all existing PT_LOADs, so appending preserves order.
	phtPTLoadOff := newPhtFileOff + uint64(phnum)*uint64(phentsize)
	binary.LittleEndian.PutUint32(out[phtPTLoadOff+transform.ElfPhdrTypeOffset:phtPTLoadOff+transform.ElfPhdrTypeOffset+4], transform.ElfPTLoad)
	binary.LittleEndian.PutUint32(out[phtPTLoadOff+transform.ElfPhdrFlagsOffset:phtPTLoadOff+transform.ElfPhdrFlagsOffset+4], transform.ElfPFR)
	binary.LittleEndian.PutUint64(out[phtPTLoadOff+transform.ElfPhdrOffsetOffset:phtPTLoadOff+transform.ElfPhdrOffsetOffset+8], newPhtFileOff)
	binary.LittleEndian.PutUint64(out[phtPTLoadOff+transform.ElfPhdrVAddrOffset:phtPTLoadOff+transform.ElfPhdrVAddrOffset+8], coverPhtVAddr)
	binary.LittleEndian.PutUint64(out[phtPTLoadOff+transform.ElfPhdrPAddrOffset:phtPTLoadOff+transform.ElfPhdrPAddrOffset+8], coverPhtVAddr)
	binary.LittleEndian.PutUint64(out[phtPTLoadOff+transform.ElfPhdrFileSzOffset:phtPTLoadOff+transform.ElfPhdrFileSzOffset+8], newPhtSize)
	binary.LittleEndian.PutUint64(out[phtPTLoadOff+transform.ElfPhdrMemSzOffset:phtPTLoadOff+transform.ElfPhdrMemSzOffset+8], newPhtSize)
	binary.LittleEndian.PutUint64(out[phtPTLoadOff+transform.ElfPhdrAlignOffset:phtPTLoadOff+transform.ElfPhdrAlignOffset+8], transform.ElfPageSize)

	// 7. Append cover PT_LOADs (indices phnum+1 … newPhnum-1).
	for i, p := range coverPlans {
		entryOff := newPhtFileOff + uint64(phnum+1+uint16(i))*uint64(phentsize)
		binary.LittleEndian.PutUint32(out[entryOff+transform.ElfPhdrTypeOffset:entryOff+transform.ElfPhdrTypeOffset+4], transform.ElfPTLoad)
		binary.LittleEndian.PutUint32(out[entryOff+transform.ElfPhdrFlagsOffset:entryOff+transform.ElfPhdrFlagsOffset+4], transform.ElfPFR)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrOffsetOffset:entryOff+transform.ElfPhdrOffsetOffset+8], p.fileOff)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrVAddrOffset:entryOff+transform.ElfPhdrVAddrOffset+8], p.vaddr)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrPAddrOffset:entryOff+transform.ElfPhdrPAddrOffset+8], p.vaddr)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrFileSzOffset:entryOff+transform.ElfPhdrFileSzOffset+8], p.size)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrMemSzOffset:entryOff+transform.ElfPhdrMemSzOffset+8], p.size)
		binary.LittleEndian.PutUint64(out[entryOff+transform.ElfPhdrAlignOffset:entryOff+transform.ElfPhdrAlignOffset+8], transform.ElfPageSize)
		if err := writeJunkBody(out[p.fileOff:p.fileOff+p.size], p.fill); err != nil {
			return nil, err
		}
	}

	// 8. Patch Ehdr: update e_phoff and e_phnum.
	binary.LittleEndian.PutUint64(out[transform.ElfEhdrPhoffOffset:transform.ElfEhdrPhoffOffset+8], newEphoff)
	binary.LittleEndian.PutUint16(out[transform.ElfEhdrPhnumOffset:transform.ElfEhdrPhnumOffset+2], newPhnum)

	// 9. Self-test: debug/elf must accept the output. This catches
	//    off-by-one errors in the PHT layout before we return broken
	//    bytes to the caller.
	if _, err := elf.NewFile(bytes.NewReader(out)); err != nil {
		return nil, fmt.Errorf("packer/cover: relocated PHT failed debug/elf self-test: %w", err)
	}

	return out, nil
}

// firstPTLoadVAddr returns the p_vaddr of the first PT_LOAD entry in
// the PHT. The caller already validated that at least one PT_LOAD
// exists, so the loop always returns before the sentinel.
func firstPTLoadVAddr(input []byte, phoff uint64, phentsize uint16, phnum uint16) uint64 {
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*uint64(phentsize)
		ptype := binary.LittleEndian.Uint32(input[off+transform.ElfPhdrTypeOffset : off+transform.ElfPhdrTypeOffset+4])
		if ptype == transform.ElfPTLoad {
			return binary.LittleEndian.Uint64(input[off+transform.ElfPhdrVAddrOffset : off+transform.ElfPhdrVAddrOffset+8])
		}
	}
	return 0 // unreachable: caller guarantees ≥1 PT_LOAD
}
