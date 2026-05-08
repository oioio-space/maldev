package packer

import (
	"encoding/binary"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// AddCoverELF is the ELF64 mirror of [AddCoverPE]. Each
// [JunkSection] becomes a new PT_LOAD program-header entry with R
// only (no W, no X). The kernel maps each PT_LOAD as ordinary
// read-only data; runtime behaviour is unchanged.
//
// ELF differs from PE in two relevant ways:
//   - The Section header table (SHT) is optional at runtime — the
//     kernel uses program headers (PHT). Cover layer adds PT_LOADs
//     to the PHT; SHT entries are NOT added (a stripped binary
//     stays stripped).
//   - PT_LOAD entries must be sorted by p_vaddr ascending. Cover
//     PT_LOADs are appended above the highest existing virtual end
//     so the ordering is preserved.
//
// The PHT is grown in place: cover layer writes new phdr slots
// after the last existing one. The input must therefore have at
// least len(JunkSections) phdr slots of slack between the PHT and
// the first PT_LOAD's file offset; real Go static-PIE binaries
// always do.
//
// JunkSection.Name is ignored on ELF — sections are not part of
// the runtime path.
//
// Returns ErrCoverInvalidOptions for empty options or non-ELF
// input; ErrCoverSectionTableFull when the PHT cannot grow.
func AddCoverELF(input []byte, opts CoverOptions) ([]byte, error) {
	if len(opts.JunkSections) == 0 {
		return nil, ErrCoverInvalidOptions
	}
	if !bytesAreLikelyELF(input) {
		return nil, fmt.Errorf("%w: not an ELF64", ErrCoverInvalidOptions)
	}

	phoff := binary.LittleEndian.Uint64(input[transform.ElfEhdrPhoffOffset : transform.ElfEhdrPhoffOffset+8])
	phentsize := binary.LittleEndian.Uint16(input[transform.ElfEhdrPhentszOffset : transform.ElfEhdrPhentszOffset+2])
	phnum := binary.LittleEndian.Uint16(input[transform.ElfEhdrPhnumOffset : transform.ElfEhdrPhnumOffset+2])
	if phentsize != transform.ElfPhdrSize {
		return nil, fmt.Errorf("%w: phentsize %d != %d", ErrCoverInvalidOptions, phentsize, transform.ElfPhdrSize)
	}

	// Locate the highest virtual end + file end across all
	// existing PT_LOADs. New cover PT_LOADs sit above them.
	var maxVEnd, maxFEnd uint64
	var firstPTLoadFileOff uint64 = ^uint64(0)
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*uint64(phentsize)
		if int(off)+int(phentsize) > len(input) {
			return nil, fmt.Errorf("%w: phdr past end of input", ErrCoverInvalidOptions)
		}
		ptype := binary.LittleEndian.Uint32(input[off+transform.ElfPhdrTypeOffset : off+transform.ElfPhdrTypeOffset+4])
		if ptype != transform.ElfPTLoad {
			continue
		}
		o := binary.LittleEndian.Uint64(input[off+transform.ElfPhdrOffsetOffset : off+transform.ElfPhdrOffsetOffset+8])
		va := binary.LittleEndian.Uint64(input[off+transform.ElfPhdrVAddrOffset : off+transform.ElfPhdrVAddrOffset+8])
		fs := binary.LittleEndian.Uint64(input[off+transform.ElfPhdrFileSzOffset : off+transform.ElfPhdrFileSzOffset+8])
		ms := binary.LittleEndian.Uint64(input[off+transform.ElfPhdrMemSzOffset : off+transform.ElfPhdrMemSzOffset+8])
		if e := transform.AlignUpU64(va+ms, transform.ElfPageSize); e > maxVEnd {
			maxVEnd = e
		}
		if e := o + fs; e > maxFEnd {
			maxFEnd = e
		}
		if o < firstPTLoadFileOff {
			firstPTLoadFileOff = o
		}
	}

	// Verify the PHT has slack for the new entries. Go static-PIE
	// binaries place the first PT_LOAD at file offset 0 (PHT lives
	// inside the segment) — the in-place grow path can never succeed
	// for them. Delegate to the relocation path instead of returning
	// ErrCoverSectionTableFull (see cover_elf_reloc.go).
	newTableEnd := phoff + uint64(uint16(phnum)+uint16(len(opts.JunkSections)))*uint64(phentsize)
	if newTableEnd > firstPTLoadFileOff {
		return relocateAndCoverELF(input, opts, phoff, phentsize, phnum,
			maxVEnd, maxFEnd)
	}

	// Plan the new PT_LOADs. Bodies are filled directly into the
	// output buffer below — no per-section intermediate alloc.
	type planned struct {
		fileOff uint64
		vaddr   uint64
		size    uint64
		fill    JunkFill
	}
	plans := make([]planned, len(opts.JunkSections))
	vCursor := transform.AlignUpU64(maxVEnd, transform.ElfPageSize)
	fCursor := transform.AlignUpU64(maxFEnd, transform.ElfPageSize)
	for i, js := range opts.JunkSections {
		paged := transform.AlignUpU64(uint64(js.Size), transform.ElfPageSize)
		plans[i] = planned{
			fileOff: fCursor,
			vaddr:   vCursor,
			size:    uint64(js.Size),
			fill:    js.Fill,
		}
		vCursor += paged
		fCursor += paged
	}

	totalSize := fCursor
	if uint64(len(input)) > totalSize {
		totalSize = uint64(len(input))
	}
	out := make([]byte, totalSize)
	copy(out, input)

	for i, p := range plans {
		off := phoff + uint64(uint16(phnum)+uint16(i))*uint64(phentsize)
		binary.LittleEndian.PutUint32(out[off+transform.ElfPhdrTypeOffset:off+transform.ElfPhdrTypeOffset+4], transform.ElfPTLoad)
		binary.LittleEndian.PutUint32(out[off+transform.ElfPhdrFlagsOffset:off+transform.ElfPhdrFlagsOffset+4], transform.ElfPFR)
		binary.LittleEndian.PutUint64(out[off+transform.ElfPhdrOffsetOffset:off+transform.ElfPhdrOffsetOffset+8], p.fileOff)
		binary.LittleEndian.PutUint64(out[off+transform.ElfPhdrVAddrOffset:off+transform.ElfPhdrVAddrOffset+8], p.vaddr)
		binary.LittleEndian.PutUint64(out[off+transform.ElfPhdrPAddrOffset:off+transform.ElfPhdrPAddrOffset+8], p.vaddr)
		binary.LittleEndian.PutUint64(out[off+transform.ElfPhdrFileSzOffset:off+transform.ElfPhdrFileSzOffset+8], p.size)
		binary.LittleEndian.PutUint64(out[off+transform.ElfPhdrMemSzOffset:off+transform.ElfPhdrMemSzOffset+8], p.size)
		binary.LittleEndian.PutUint64(out[off+transform.ElfPhdrAlignOffset:off+transform.ElfPhdrAlignOffset+8], transform.ElfPageSize)
		if err := writeJunkBody(out[p.fileOff:p.fileOff+p.size], p.fill); err != nil {
			return nil, err
		}
	}

	// Bump e_phnum.
	binary.LittleEndian.PutUint16(out[transform.ElfEhdrPhnumOffset:transform.ElfEhdrPhnumOffset+2], phnum+uint16(len(opts.JunkSections)))

	return out, nil
}

// bytesAreLikelyELF checks the ELF magic + EI_CLASS=64 + EI_DATA=LE
// without doing a full PHT walk.
func bytesAreLikelyELF(input []byte) bool {
	if len(input) < transform.ElfEhdrSize {
		return false
	}
	if input[0] != 0x7F || input[1] != 'E' || input[2] != 'L' || input[3] != 'F' {
		return false
	}
	return input[4] == 2 && input[5] == 1
}


