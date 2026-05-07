package packer

import (
	"encoding/binary"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// ELF64 layout constants. The transform package keeps its own
// unexported copies of overlapping fields (Phdr offsets, page
// size); promoting those into a shared exported set is a separate
// chantier. Until then the cover layer carries this small set.
const (
	elfEhdrSizeC         = 64
	elfPhdrSizeC         = 56
	elfPageSizeC  uint64 = 0x1000

	ehdrPhoffOff   = 0x20
	ehdrPhentszOff = 0x36
	ehdrPhnumOff   = 0x38

	phdrTypeOff   = 0x00
	phdrFlagsOff  = 0x04
	phdrOffsetOff = 0x08
	phdrVAddrOff  = 0x10
	phdrPAddrOff  = 0x18
	phdrFileSzOff = 0x20
	phdrMemSzOff  = 0x28
	phdrAlignOff  = 0x30

	pfReadC uint32 = 4
	ptLoadC uint32 = 1
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

	phoff := binary.LittleEndian.Uint64(input[ehdrPhoffOff : ehdrPhoffOff+8])
	phentsize := binary.LittleEndian.Uint16(input[ehdrPhentszOff : ehdrPhentszOff+2])
	phnum := binary.LittleEndian.Uint16(input[ehdrPhnumOff : ehdrPhnumOff+2])
	if phentsize != elfPhdrSizeC {
		return nil, fmt.Errorf("%w: phentsize %d != %d", ErrCoverInvalidOptions, phentsize, elfPhdrSizeC)
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
		ptype := binary.LittleEndian.Uint32(input[off+phdrTypeOff : off+phdrTypeOff+4])
		if ptype != ptLoadC {
			continue
		}
		o := binary.LittleEndian.Uint64(input[off+phdrOffsetOff : off+phdrOffsetOff+8])
		va := binary.LittleEndian.Uint64(input[off+phdrVAddrOff : off+phdrVAddrOff+8])
		fs := binary.LittleEndian.Uint64(input[off+phdrFileSzOff : off+phdrFileSzOff+8])
		ms := binary.LittleEndian.Uint64(input[off+phdrMemSzOff : off+phdrMemSzOff+8])
		if e := transform.AlignUpU64(va+ms, elfPageSizeC); e > maxVEnd {
			maxVEnd = e
		}
		if e := o + fs; e > maxFEnd {
			maxFEnd = e
		}
		if o < firstPTLoadFileOff {
			firstPTLoadFileOff = o
		}
	}

	// Verify the PHT has slack for the new entries.
	newTableEnd := phoff + uint64(uint16(phnum)+uint16(len(opts.JunkSections)))*uint64(phentsize)
	if newTableEnd > firstPTLoadFileOff {
		return nil, ErrCoverSectionTableFull
	}

	// Plan the new PT_LOADs.
	type planned struct {
		fileOff uint64
		vaddr   uint64
		size    uint64
		body    []byte
	}
	plans := make([]planned, len(opts.JunkSections))
	vCursor := transform.AlignUpU64(maxVEnd, elfPageSizeC)
	fCursor := transform.AlignUpU64(maxFEnd, elfPageSizeC)
	for i, js := range opts.JunkSections {
		body, err := generateJunkBody(js.Size, js.Fill)
		if err != nil {
			return nil, err
		}
		paged := transform.AlignUpU64(uint64(js.Size), elfPageSizeC)
		plans[i] = planned{
			fileOff: fCursor,
			vaddr:   vCursor,
			size:    uint64(js.Size),
			body:    body,
		}
		vCursor += paged
		fCursor += paged
	}

	// Build output buffer.
	totalSize := fCursor
	if uint64(len(input)) > totalSize {
		totalSize = uint64(len(input))
	}
	out := make([]byte, totalSize)
	copy(out, input)

	// Patch new phdr slots.
	for i, p := range plans {
		off := phoff + uint64(uint16(phnum)+uint16(i))*uint64(phentsize)
		binary.LittleEndian.PutUint32(out[off+phdrTypeOff:off+phdrTypeOff+4], ptLoadC)
		binary.LittleEndian.PutUint32(out[off+phdrFlagsOff:off+phdrFlagsOff+4], pfReadC)
		binary.LittleEndian.PutUint64(out[off+phdrOffsetOff:off+phdrOffsetOff+8], p.fileOff)
		binary.LittleEndian.PutUint64(out[off+phdrVAddrOff:off+phdrVAddrOff+8], p.vaddr)
		binary.LittleEndian.PutUint64(out[off+phdrPAddrOff:off+phdrPAddrOff+8], p.vaddr)
		binary.LittleEndian.PutUint64(out[off+phdrFileSzOff:off+phdrFileSzOff+8], p.size)
		binary.LittleEndian.PutUint64(out[off+phdrMemSzOff:off+phdrMemSzOff+8], p.size)
		binary.LittleEndian.PutUint64(out[off+phdrAlignOff:off+phdrAlignOff+8], elfPageSizeC)
		copy(out[p.fileOff:p.fileOff+uint64(len(p.body))], p.body)
	}

	// Bump e_phnum.
	binary.LittleEndian.PutUint16(out[ehdrPhnumOff:ehdrPhnumOff+2], phnum+uint16(len(opts.JunkSections)))

	return out, nil
}

// bytesAreLikelyELF checks the ELF magic + EI_CLASS=64 + EI_DATA=LE
// without doing a full PHT walk.
func bytesAreLikelyELF(input []byte) bool {
	if len(input) < elfEhdrSizeC {
		return false
	}
	if input[0] != 0x7F || input[1] != 'E' || input[2] != 'L' || input[3] != 'F' {
		return false
	}
	return input[4] == 2 && input[5] == 1
}


