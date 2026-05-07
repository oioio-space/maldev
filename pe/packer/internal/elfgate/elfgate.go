// Package elfgate implements the Z-scope pre-flight check for
// Go static-PIE ELF inputs: ET_DYN + .go.buildinfo present +
// no DT_NEEDED. Both the packer package (operator-facing
// ValidateELF) and the runtime sub-package (Prepare) share this
// logic to avoid duplication without creating an import cycle.
package elfgate

import (
	"bytes"
	"debug/buildinfo"
	"encoding/binary"
	"errors"
	"fmt"
)

// Sentinels used by [CheckELFLoadable]. Shared with
// pe/packer/runtime via package-level delegation so callers can
// errors.Is against them regardless of which package surface they
// called.
var (
	// ErrBadELF fires on header-walk inconsistencies (truncated,
	// bad magic, impossible field values).
	ErrBadELF = errors.New("packer/runtime: malformed ELF")

	// ErrUnsupportedELFArch fires when the ELF is not 64-bit
	// little-endian x86_64.
	ErrUnsupportedELFArch = errors.New("packer/runtime: only ELF64 little-endian x86_64 is supported")

	// ErrNotELFExec fires when the ELF type is neither ET_EXEC
	// nor ET_DYN.
	ErrNotELFExec = errors.New("packer/runtime: only ET_EXEC and ET_DYN images are supported")

	// ErrNotImplemented fires for inputs that pass structural
	// validation but fail the Z-scope Go static-PIE gate.
	ErrNotImplemented = errors.New("packer/runtime: backend not yet implemented")
)

// ELF on-wire constants. Names mirror the System V gABI / Linux
// elf(5) so future contributors can grep against the standard.
const (
	ElfMagic0 = 0x7F
	ElfMagic1 = 'E'
	ElfMagic2 = 'L'
	ElfMagic3 = 'F'

	elfClass64 = 2 // EI_CLASS = ELFCLASS64
	elfDataLE  = 1 // EI_DATA  = ELFDATA2LSB

	etExec = 2 // ET_EXEC
	etDyn  = 3 // ET_DYN

	emX86_64 = 62 // EM_X86_64

	ptLoad    = 1 // PT_LOAD
	ptDynamic = 2 // PT_DYNAMIC
	ptInterp  = 3 // PT_INTERP
	PtTLS     = 7 // PT_TLS — exported so runtime_linux.go can use it

	dtNull   = 0 // DT_NULL
	dtNeeded = 1 // DT_NEEDED

	ELFHeaderSize  = 64 // sizeof(Elf64_Ehdr)
	ELFProgHdrSize = 56 // sizeof(Elf64_Phdr)
)

// ELFHeaders is the parsed-out subset of the ELF header + program
// header table the loader needs. Exported so pe/packer/runtime can
// reuse the parse result in its mapper without re-parsing.
type ELFHeaders struct {
	ELFType   uint16 // e_type — ET_EXEC or ET_DYN
	Entry     uint64 // e_entry — virtual address
	Phoff     uint64 // e_phoff — file offset of program header table
	Phnum     uint16 // e_phnum — number of program headers
	Phentsize uint16 // e_phentsize — must be ELFProgHdrSize on ELF64

	// Programs is the parsed program header table. Order preserved
	// so the mapper can iterate in declaration order.
	Programs []ELFProgramHeader

	// IsStaticPIE is true when the ELF satisfies the structural
	// static-PIE contract: ET_DYN + no DT_NEEDED + at least one
	// PT_LOAD. Phase 1f Stage E broadened the gate from
	// "Go static-PIE only" to any self-contained ELF — Go,
	// hand-rolled asm, and C/Rust built with -static-pie all
	// pass when they meet the structural definition.
	IsStaticPIE bool

	// GoVersion is the Go toolchain version string parsed via
	// debug/buildinfo when the ELF carries a .go.buildinfo
	// section. Empty for non-Go binaries (asm, C/Rust). Useful
	// purely for diagnostics — a non-empty value tells callers
	// "this was built by Go go<X>" without affecting whether the
	// binary is loadable (which IsStaticPIE owns).
	GoVersion string

	// HasDTNeeded is true when PT_DYNAMIC carries at least one
	// DT_NEEDED entry. Used by GateRejectionReason.
	HasDTNeeded bool
}

// ELFProgramHeader is one Elf64_Phdr entry.
type ELFProgramHeader struct {
	Type   uint32 // p_type
	Flags  uint32 // p_flags
	Offset uint64 // p_offset
	VAddr  uint64 // p_vaddr
	PAddr  uint64 // p_paddr
	FileSz uint64 // p_filesz
	MemSz  uint64 // p_memsz
	Align  uint64 // p_align
}

// CheckELFLoadable returns nil when input is a self-contained
// static-PIE the Linux runtime can load, or a wrapped sentinel
// explaining the rejection. Cross-platform — pure parse, no
// syscalls.
//
// Stage E contract: ET_DYN + no DT_NEEDED + at least one PT_LOAD.
// Go-built (Stage C+D), hand-rolled asm, and C/Rust binaries
// produced by `-static-pie` all pass when they meet the
// structural definition.
func CheckELFLoadable(input []byte) error {
	if len(input) < 4 {
		return fmt.Errorf("%w: input shorter than ELF magic", ErrBadELF)
	}
	if input[0] != ElfMagic0 || input[1] != ElfMagic1 ||
		input[2] != ElfMagic2 || input[3] != ElfMagic3 {
		return fmt.Errorf("%w: not an ELF (magic % x)", ErrBadELF, input[:4])
	}
	h, err := ParseELFHeaders(input)
	if err != nil {
		return err
	}
	if h.ELFType != etDyn {
		return fmt.Errorf("%w: ET_EXEC not supported (need PIE / ET_DYN)", ErrNotImplemented)
	}
	if !h.IsStaticPIE {
		return fmt.Errorf("%w: %s", ErrNotImplemented, h.GateRejectionReason())
	}
	return nil
}

// ParseELFHeaders walks the on-wire ELF64 structure. Strict —
// rejects malformed or unsupported inputs early so the mapper
// never allocates against a bogus SizeOfImage.
func ParseELFHeaders(in []byte) (*ELFHeaders, error) {
	if len(in) < ELFHeaderSize {
		return nil, fmt.Errorf("%w: input too small for ELF64 header (%d < %d)",
			ErrBadELF, len(in), ELFHeaderSize)
	}
	if in[0] != ElfMagic0 || in[1] != ElfMagic1 || in[2] != ElfMagic2 || in[3] != ElfMagic3 {
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

	h := &ELFHeaders{
		ELFType:   elfType,
		Entry:     binary.LittleEndian.Uint64(in[24:32]),
		Phoff:     binary.LittleEndian.Uint64(in[32:40]),
		Phentsize: binary.LittleEndian.Uint16(in[54:56]),
		Phnum:     binary.LittleEndian.Uint16(in[56:58]),
	}
	if h.Phentsize != ELFProgHdrSize {
		return nil, fmt.Errorf("%w: e_phentsize=%d, expected %d for ELF64",
			ErrBadELF, h.Phentsize, ELFProgHdrSize)
	}
	if h.Phnum == 0 {
		return nil, fmt.Errorf("%w: zero program headers", ErrBadELF)
	}
	end := int(h.Phoff) + int(h.Phnum)*int(h.Phentsize)
	if end > len(in) || end < 0 {
		return nil, fmt.Errorf("%w: program headers past end of buffer (%d > %d)",
			ErrBadELF, end, len(in))
	}

	h.Programs = make([]ELFProgramHeader, h.Phnum)
	for i := 0; i < int(h.Phnum); i++ {
		off := int(h.Phoff) + i*int(h.Phentsize)
		h.Programs[i] = ELFProgramHeader{
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

	// At least one PT_LOAD must exist or there's nothing to map.
	hasLoad := false
	for _, p := range h.Programs {
		if p.Type == ptLoad {
			hasLoad = true
			break
		}
	}
	if !hasLoad {
		return nil, fmt.Errorf("%w: no PT_LOAD program headers", ErrBadELF)
	}

	h.IsStaticPIE, h.GoVersion = detectStaticPIE(in, h)
	return h, nil
}

// detectStaticPIE runs the structural static-PIE gate after the
// program-header walk: ET_DYN + no DT_NEEDED. PT_INTERP is allowed
// when DT_NEEDED is absent because the dynamic linker is never
// invoked without shared libraries to resolve. The .go.buildinfo
// section is no longer required for the gate decision (Stage E
// broadening); when present, GoVersion is populated for diagnostic
// purposes only — the loader treats Go and non-Go static-PIE the
// same way.
func detectStaticPIE(input []byte, h *ELFHeaders) (bool, string) {
	h.HasDTNeeded = !dynamicHasNoNeeded(input, h)
	if h.ELFType != etDyn {
		return false, ""
	}
	if h.HasDTNeeded {
		return false, ""
	}
	// .go.buildinfo presence is purely informational from Stage E
	// onwards. A read failure means "not a Go binary"; the gate
	// still accepts the binary as long as the structural checks
	// pass.
	if bi, err := buildinfo.Read(bytes.NewReader(input)); err == nil {
		return true, bi.GoVersion
	}
	return true, ""
}

// dynamicHasNoNeeded returns true when PT_DYNAMIC carries zero
// DT_NEEDED entries, or when there is no PT_DYNAMIC at all.
func dynamicHasNoNeeded(input []byte, h *ELFHeaders) bool {
	for _, p := range h.Programs {
		if p.Type != ptDynamic {
			continue
		}
		end := p.Offset + p.FileSz
		if end > uint64(len(input)) || end < p.Offset {
			return false
		}
		dyn := input[p.Offset:end]
		for off := 0; off+16 <= len(dyn); off += 16 {
			tag := int64(binary.LittleEndian.Uint64(dyn[off : off+8]))
			if tag == dtNull {
				break
			}
			if tag == dtNeeded {
				return false
			}
		}
	}
	return true
}

// GateRejectionReason returns the specific structural condition
// that failed, for embedding in an ErrNotImplemented message.
// Returns "" when IsStaticPIE is true.
//
// Two failure modes after Stage E:
//   - "not ET_DYN (need PIE)" — non-PIE ELF (ET_EXEC / ET_REL).
//   - "has DT_NEEDED entries (not a static binary)" — dynamically
//     linked ELF; rebuild with `-static-pie` (or for Go,
//     `-buildmode=pie -ldflags='-s -w'` with CGO_ENABLED=0).
func (h *ELFHeaders) GateRejectionReason() string {
	if h.IsStaticPIE {
		return ""
	}
	if h.ELFType != etDyn {
		return "not ET_DYN (need PIE)"
	}
	if h.HasDTNeeded {
		return "has DT_NEEDED entries (not a static binary)"
	}
	// Reachable only if some future check is added to detectStaticPIE
	// without a matching branch here. Defensive sentinel — keeps the
	// function's contract obvious to future contributors.
	return "structural static-PIE check failed (unknown reason)"
}
