package runtime_test

import (
	"encoding/binary"
	"testing"
)

// dirEntry mirrors the on-wire IMAGE_DATA_DIRECTORY (8 bytes:
// VirtualAddress + Size) used in the optional header.
type dirEntry struct {
	VirtualAddress uint32
	Size           uint32
}

// headerOpts shape what buildHeaderOnlyPE emits. Only fields
// the parse-rejection tests need are wired today; extend
// per-test as new test cases land.
type headerOpts struct {
	Machine         uint16 // COFF File Header Machine
	OptMagic        uint16 // Optional Header Magic (0x10B = PE32, 0x20B = PE32+)
	Characteristics uint16 // COFF File Header Characteristics (0x2000 = DLL)
	TLSDir          dirEntry
}

// elfHeaderOpts shapes what buildHeaderOnlyELF emits. Only fields
// the parse-rejection / dispatch tests need are wired today.
type elfHeaderOpts struct {
	Class   uint8  // EI_CLASS — 2 = ELF64 (default), 1 = ELF32
	Data    uint8  // EI_DATA  — 1 = LE (default), 2 = BE
	Type    uint16 // e_type   — 2 = ET_EXEC (default), 3 = ET_DYN
	Machine uint16 // e_machine — 62 = EM_X86_64 (default)
	Entry   uint64
	NoLoad  bool // emit zero PT_LOAD segments to trip the no-load check

	// Stage B knobs — append extra Phdrs after the default PT_LOAD
	// to exercise the rejection paths in mapAndRelocateELF.
	WithInterp bool // emit a PT_INTERP segment (Stage B rejects)
	WithTLS    bool // emit a PT_TLS segment    (Stage B rejects)

	// WithDynamic emits a PT_DYNAMIC segment whose body is a
	// 16-byte DT_NULL terminator and tunes the PT_LOAD to cover
	// the whole file. With Type=ET_DYN this produces the smallest
	// possible mappable PIE — no relocations, no symbols. Used
	// for the Stage B happy-path test.
	WithDynamic bool
}

// buildMinimalELF writes a 64-byte Elf64_Ehdr followed by one
// Phdr (sized 56 bytes) so parseELFHeaders reaches the rejection
// path matching the scenario. Defaults select a valid ELF64 LE
// x86_64 ET_EXEC with one PT_LOAD segment and no body.
func buildMinimalELF(t *testing.T, o elfHeaderOpts) []byte {
	t.Helper()
	if o.Class == 0 {
		o.Class = 2
	}
	if o.Data == 0 {
		o.Data = 1
	}
	if o.Type == 0 {
		o.Type = 2 // ET_EXEC
	}
	if o.Machine == 0 {
		o.Machine = 62 // EM_X86_64
	}

	const ehdrSize = 64
	const phdrSize = 56
	phnum := uint16(1)
	if o.WithInterp {
		phnum++
	}
	if o.WithTLS {
		phnum++
	}
	if o.WithDynamic {
		phnum++
	}
	totalSize := ehdrSize + int(phnum)*phdrSize
	dynOff := totalSize // where the DT_NULL terminator lives
	if o.WithDynamic {
		totalSize += 16 // 16-byte DT_NULL entry
	}
	out := make([]byte, totalSize)

	// e_ident
	out[0], out[1], out[2], out[3] = 0x7F, 'E', 'L', 'F'
	out[4] = o.Class
	out[5] = o.Data
	out[6] = 1 // EI_VERSION
	// e_type, e_machine
	binary.LittleEndian.PutUint16(out[16:18], o.Type)
	binary.LittleEndian.PutUint16(out[18:20], o.Machine)
	binary.LittleEndian.PutUint32(out[20:24], 1) // e_version
	binary.LittleEndian.PutUint64(out[24:32], o.Entry)
	binary.LittleEndian.PutUint64(out[32:40], ehdrSize) // e_phoff
	binary.LittleEndian.PutUint16(out[54:56], phdrSize) // e_phentsize
	binary.LittleEndian.PutUint16(out[56:58], phnum)    // e_phnum

	// First Phdr is always PT_LOAD (or PT_NOTE for the NoLoad
	// rejection path). When WithDynamic is set, this PT_LOAD
	// covers the entire file so the dynamic section is mapped.
	off := ehdrSize
	pType := uint32(1)
	if o.NoLoad {
		pType = 4 // PT_NOTE — trips the "no PT_LOAD" guard
	}
	binary.LittleEndian.PutUint32(out[off:off+4], pType)
	binary.LittleEndian.PutUint32(out[off+4:off+8], 5) // PF_R | PF_X
	if o.WithDynamic {
		// PT_LOAD: offset=0, vaddr=0, filesz=memsz=totalSize.
		// Headers + DT_NULL all sit inside one mapped segment.
		binary.LittleEndian.PutUint64(out[off+8:off+16], 0)                  // p_offset
		binary.LittleEndian.PutUint64(out[off+16:off+24], 0)                 // p_vaddr
		binary.LittleEndian.PutUint64(out[off+24:off+32], 0)                 // p_paddr
		binary.LittleEndian.PutUint64(out[off+32:off+40], uint64(totalSize)) // p_filesz
		binary.LittleEndian.PutUint64(out[off+40:off+48], uint64(totalSize)) // p_memsz
		binary.LittleEndian.PutUint64(out[off+48:off+56], 0x1000)            // p_align
	}
	off += phdrSize

	if o.WithInterp {
		binary.LittleEndian.PutUint32(out[off:off+4], 3) // PT_INTERP
		binary.LittleEndian.PutUint32(out[off+4:off+8], 4)
		off += phdrSize
	}
	if o.WithTLS {
		binary.LittleEndian.PutUint32(out[off:off+4], 7) // PT_TLS
		binary.LittleEndian.PutUint32(out[off+4:off+8], 4)
		off += phdrSize
	}
	if o.WithDynamic {
		binary.LittleEndian.PutUint32(out[off:off+4], 2) // PT_DYNAMIC
		binary.LittleEndian.PutUint32(out[off+4:off+8], 6) // PF_R | PF_W
		binary.LittleEndian.PutUint64(out[off+8:off+16], uint64(dynOff))   // p_offset
		binary.LittleEndian.PutUint64(out[off+16:off+24], uint64(dynOff))  // p_vaddr
		binary.LittleEndian.PutUint64(out[off+24:off+32], uint64(dynOff))  // p_paddr
		binary.LittleEndian.PutUint64(out[off+32:off+40], 16)              // p_filesz (just DT_NULL)
		binary.LittleEndian.PutUint64(out[off+40:off+48], 16)              // p_memsz
		binary.LittleEndian.PutUint64(out[off+48:off+56], 8)               // p_align
		// out[dynOff..dynOff+16] stays zero — that's exactly DT_NULL,
		// which terminates the dynamic walk before any DT_RELA.
	}

	return out
}

// buildHeaderOnlyPE writes a minimal-but-valid-enough PE that
// the loader's parseHeaders walk reaches the rejection check
// matching the test scenario. The body after the headers is
// zeroed; no sections are emitted because the rejection paths
// always trip before the section-table walk.
func buildHeaderOnlyPE(t *testing.T, o headerOpts) []byte {
	t.Helper()
	const peOff = 0x40
	const optHdrSize = 240 // PE32+ Optional Header
	const headersSize = peOff + 4 + 20 + optHdrSize

	pe := make([]byte, headersSize)

	// DOS header: just the magic and e_lfanew at offset 60.
	pe[0] = 'M'
	pe[1] = 'Z'
	binary.LittleEndian.PutUint32(pe[60:64], peOff)

	// PE signature.
	binary.LittleEndian.PutUint32(pe[peOff:peOff+4], 0x00004550)

	// COFF File Header (20 bytes starting at peOff+4).
	cof := peOff + 4
	binary.LittleEndian.PutUint16(pe[cof:cof+2], o.Machine)
	binary.LittleEndian.PutUint16(pe[cof+2:cof+4], 0) // NumberOfSections
	// SizeOfOptionalHeader = optHdrSize:
	binary.LittleEndian.PutUint16(pe[cof+16:cof+18], optHdrSize)
	binary.LittleEndian.PutUint16(pe[cof+18:cof+20], o.Characteristics)

	// Optional Header.
	opt := cof + 20
	binary.LittleEndian.PutUint16(pe[opt:opt+2], o.OptMagic)

	// Data directories live at opt+112 in PE32+. Each entry is 8
	// bytes (VA + Size). TLS is index 9 → off = opt + 112 + 9*8.
	if o.OptMagic == 0x20B {
		tlsOff := opt + 112 + 9*8
		binary.LittleEndian.PutUint32(pe[tlsOff:tlsOff+4], o.TLSDir.VirtualAddress)
		binary.LittleEndian.PutUint32(pe[tlsOff+4:tlsOff+8], o.TLSDir.Size)
	}

	return pe
}
