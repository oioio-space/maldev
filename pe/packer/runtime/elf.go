package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ELF format sentinels surfaced by [Prepare] when the input is
// an ELF binary. PE inputs surface [ErrBadPE] / [ErrUnsupportedArch]
// / [ErrNotEXE] from runtime.go instead.
var (
	// ErrBadELF fires on header-walk inconsistencies (truncated,
	// bad magic, impossible field values).
	ErrBadELF = errors.New("packer/runtime: malformed ELF")

	// ErrUnsupportedELFArch fires when the ELF is not 64-bit
	// little-endian x86_64. 32-bit, big-endian, ARM64 are out
	// of scope.
	ErrUnsupportedELFArch = errors.New("packer/runtime: only ELF64 little-endian x86_64 is supported")

	// ErrNotELFExec fires when the ELF type is neither ET_EXEC
	// nor ET_DYN. Object files (ET_REL), core files (ET_CORE),
	// and exotic types are out of scope.
	ErrNotELFExec = errors.New("packer/runtime: only ET_EXEC and ET_DYN images are supported")

	// ErrFormatPlatformMismatch fires when an ELF is fed to the
	// Windows backend or a PE to the Linux backend. Operators
	// must pack a host-matching binary.
	ErrFormatPlatformMismatch = errors.New("packer/runtime: format does not match host platform")

	// ErrNotImplemented fires for backends that exist but haven't
	// landed their map+relocate path yet (e.g. Linux ELF in
	// Phase 1f Stage A — parser shipped, mapper deferred).
	ErrNotImplemented = errors.New("packer/runtime: backend not yet implemented")

	// ErrNotWindows fires from the long-tail stub on platforms
	// other than Windows / Linux. Defined cross-platform so test
	// code can compare against it via errors.Is regardless of
	// build host.
	ErrNotWindows = errors.New("packer/runtime: reflective loader not supported on this OS")
)

// ELF on-wire constants. Names mirror the System V gABI / Linux
// elf(5) so future contributors can grep against the standard.
const (
	elfMagic0 = 0x7F
	elfMagic1 = 'E'
	elfMagic2 = 'L'
	elfMagic3 = 'F'

	elfClass64 = 2 // EI_CLASS = ELFCLASS64
	elfDataLE  = 1 // EI_DATA  = ELFDATA2LSB

	etExec = 2 // ET_EXEC — non-PIE executable
	etDyn  = 3 // ET_DYN  — shared object or PIE executable

	emX86_64 = 62 // EM_X86_64

	ptLoad    = 1 // PT_LOAD    — loadable segment
	ptDynamic = 2 // PT_DYNAMIC — dynamic linking info
	ptInterp  = 3 // PT_INTERP  — path of program interpreter
	ptTLS     = 7 // PT_TLS     — thread-local storage template

	pfX = 1 // PF_X — execute
	pfW = 2 // PF_W — write
	pfR = 4 // PF_R — read

	elfHeaderSize  = 64 // sizeof(Elf64_Ehdr)
	elfProgHdrSize = 56 // sizeof(Elf64_Phdr)
)

// elfHeaders is the parsed-out subset of the ELF header + program
// header table the loader actually needs. Stays unexported so the
// public surface remains [PreparedImage] regardless of format.
type elfHeaders struct {
	elfType   uint16 // e_type — ET_EXEC or ET_DYN
	entry     uint64 // e_entry — virtual address
	phoff     uint64 // e_phoff — file offset of program header table
	phnum     uint16 // e_phnum — number of program headers
	phentsize uint16 // e_phentsize — must be elfProgHdrSize on ELF64

	// programs is the parsed program header table. Order
	// preserved so the mapper can iterate in declaration order
	// (ld.so does the same; some segments depend on adjacent ones).
	programs []elfProgramHeader
}

// elfProgramHeader is one Elf64_Phdr entry. Field names match
// the gABI for greppability.
type elfProgramHeader struct {
	Type   uint32 // p_type
	Flags  uint32 // p_flags
	Offset uint64 // p_offset — file offset
	VAddr  uint64 // p_vaddr — virtual address
	PAddr  uint64 // p_paddr — physical address (ignored on Linux)
	FileSz uint64 // p_filesz — bytes in file
	MemSz  uint64 // p_memsz — bytes in memory (≥ FileSz; tail is .bss)
	Align  uint64 // p_align — alignment requirement
}

// parseELFHeaders walks the on-wire ELF64 structure (Ehdr + Phdr
// table). Strict — rejects malformed or unsupported inputs early
// so the mapper never allocates against a bogus SizeOfImage.
//
// Stage A consumer: [Prepare]'s magic-dispatch path. Stage B+
// will hand the parsed headers to the Linux mapper.
func parseELFHeaders(in []byte) (*elfHeaders, error) {
	if len(in) < elfHeaderSize {
		return nil, fmt.Errorf("%w: input too small for ELF64 header (%d < %d)",
			ErrBadELF, len(in), elfHeaderSize)
	}
	if in[0] != elfMagic0 || in[1] != elfMagic1 || in[2] != elfMagic2 || in[3] != elfMagic3 {
		return nil, fmt.Errorf("%w: missing ELF magic (got % x)", ErrBadELF, in[:4])
	}
	if in[4] != elfClass64 {
		return nil, fmt.Errorf("%w: not ELF64 (e_ident[EI_CLASS]=%d)", ErrUnsupportedELFArch, in[4])
	}
	if in[5] != elfDataLE {
		return nil, fmt.Errorf("%w: not little-endian (e_ident[EI_DATA]=%d)",
			ErrUnsupportedELFArch, in[5])
	}

	elfType := binary.LittleEndian.Uint16(in[16:18])
	machine := binary.LittleEndian.Uint16(in[18:20])
	if machine != emX86_64 {
		return nil, fmt.Errorf("%w: e_machine=%d", ErrUnsupportedELFArch, machine)
	}
	if elfType != etExec && elfType != etDyn {
		return nil, fmt.Errorf("%w: e_type=%d", ErrNotELFExec, elfType)
	}

	h := &elfHeaders{
		elfType:   elfType,
		entry:     binary.LittleEndian.Uint64(in[24:32]),
		phoff:     binary.LittleEndian.Uint64(in[32:40]),
		phentsize: binary.LittleEndian.Uint16(in[54:56]),
		phnum:     binary.LittleEndian.Uint16(in[56:58]),
	}
	if h.phentsize != elfProgHdrSize {
		return nil, fmt.Errorf("%w: e_phentsize=%d, expected %d for ELF64",
			ErrBadELF, h.phentsize, elfProgHdrSize)
	}
	if h.phnum == 0 {
		return nil, fmt.Errorf("%w: zero program headers", ErrBadELF)
	}
	end := int(h.phoff) + int(h.phnum)*int(h.phentsize)
	if end > len(in) || end < 0 {
		return nil, fmt.Errorf("%w: program headers past end of buffer (%d > %d)",
			ErrBadELF, end, len(in))
	}

	h.programs = make([]elfProgramHeader, h.phnum)
	for i := 0; i < int(h.phnum); i++ {
		off := int(h.phoff) + i*int(h.phentsize)
		h.programs[i] = elfProgramHeader{
			Type:   binary.LittleEndian.Uint32(in[off : off+4]),
			Flags:  binary.LittleEndian.Uint32(in[off+4 : off+8]),
			Offset: binary.LittleEndian.Uint64(in[off+8 : off+16]),
			VAddr:  binary.LittleEndian.Uint64(in[off+16 : off+24]),
			PAddr:  binary.LittleEndian.Uint64(in[off+24 : off+32]),
			FileSz: binary.LittleEndian.Uint64(in[off+32 : off+40]),
			MemSz:  binary.LittleEndian.Uint64(in[off+40 : off+48]),
			Align:  binary.LittleEndian.Uint64(in[off+48 : off+56]),
		}
	}

	// Defensive: at least one PT_LOAD must exist or there's
	// nothing to map. Stops early before the platform backend
	// allocates.
	hasLoad := false
	for _, p := range h.programs {
		if p.Type == ptLoad {
			hasLoad = true
			break
		}
	}
	if !hasLoad {
		return nil, fmt.Errorf("%w: no PT_LOAD program headers", ErrBadELF)
	}

	return h, nil
}
