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

	// WithNeeded emits a PT_DYNAMIC segment that contains one
	// DT_NEEDED entry followed by a DT_NULL terminator. Used to
	// exercise the DT_NEEDED rejection path in detectGoStaticPIE /
	// gateRejectionReason. Mutually exclusive with WithDynamic.
	WithNeeded bool

	// WithGoBuildInfo embeds a minimal debug/buildinfo blob and a
	// .go.buildinfo section header, satisfying the detectGoStaticPIE
	// Z-scope gate. Tests that need to exercise mapper logic past the
	// gate (happy-path, missing-PT_DYNAMIC, etc.) set this without
	// needing a real compiled binary.
	//
	// Combine with WithDynamic when PT_DYNAMIC is also required (e.g.
	// the happy-path mapper test). Omit WithDynamic when specifically
	// testing the missing-PT_DYNAMIC rejection path.
	WithGoBuildInfo bool
}

// buildInfoBlob returns a minimal debug/buildinfo-compatible blob
// (32-byte header + inline version "go1.21.0" + empty mod string)
// that satisfies debug/buildinfo.Read via a .go.buildinfo section header.
//
// Format (Go ≥ 1.18, flagsVersionInl):
//
//	[0:14]  buildInfoMagic "\xff Go buildinf:"
//	[14]    ptrSize = 8 (x86-64)
//	[15]    flags   = 0x02 (flagsVersionInl)
//	[16:32] padding (zeros)
//	[32:]   varint(len("go1.21.0")) + "go1.21.0" + varint(0)
//
// Note: debug/buildinfo.Read requires a .go.buildinfo section header entry
// (not just the magic bytes in a writable PT_LOAD). The section header
// approach mirrors what the real Go linker emits.
func buildInfoBlob() []byte {
	const magic = "\xff Go buildinf:"
	const version = "go1.21.0"
	blob := make([]byte, 32+1+len(version)+1)
	copy(blob[0:14], magic)
	blob[14] = 8    // ptrSize
	blob[15] = 0x02 // flagsVersionInl
	// inline strings start at offset 32
	blob[32] = byte(len(version)) // varint length (fits in one byte)
	copy(blob[33:], version)
	blob[33+len(version)] = 0x00 // empty mod string (varint 0)
	return blob
}

// appendSectionHeaders appends a minimal section header table to out that
// includes a .go.buildinfo section at biOff/biSize. Returns the extended
// slice and also updates the ELF header in place (e_shoff, e_shnum,
// e_shstrndx). The section header is what debug/buildinfo.DataStart() uses
// to locate the blob — the PT_LOAD fallback path is unreliable without it.
//
// Sections emitted: [0] null  [1] .go.buildinfo  [2] .shstrtab
func appendSectionHeaders(out []byte, biOff, biSize int) []byte {
	// Section name string table: \x00 + ".go.buildinfo\x00" + ".shstrtab\x00"
	//   offset 0 → ""  (null section)
	//   offset 1 → ".go.buildinfo"
	//   offset 15 → ".shstrtab"
	strtab := []byte("\x00.go.buildinfo\x00.shstrtab\x00")
	strtabOff := len(out)
	out = append(out, strtab...)

	// Section header table: 3 × 64-byte Elf64_Shdr.
	const shdrsz = 64
	if rem := len(out) % 8; rem != 0 {
		out = append(out, make([]byte, 8-rem)...) // align to 8
	}
	shtOff := len(out)
	out = append(out, make([]byte, 3*shdrsz)...)

	// sh[0]: null — already zero.

	// sh[1]: .go.buildinfo — SHT_PROGBITS, SHF_WRITE|SHF_ALLOC
	// Elf64_Shdr layout: name[0:4] type[4:8] flags[8:16] addr[16:24]
	//   offset[24:32] size[32:40] link[40:44] info[44:48]
	//   addralign[48:56] entsize[56:64]
	sh1 := out[shtOff+shdrsz:]
	binary.LittleEndian.PutUint32(sh1[0:4], 1)                // sh_name = 1
	binary.LittleEndian.PutUint32(sh1[4:8], 1)                // sh_type = SHT_PROGBITS
	binary.LittleEndian.PutUint64(sh1[8:16], 3)               // sh_flags = SHF_WRITE|SHF_ALLOC
	binary.LittleEndian.PutUint64(sh1[16:24], uint64(biOff))  // sh_addr (vaddr == file off)
	binary.LittleEndian.PutUint64(sh1[24:32], uint64(biOff))  // sh_offset
	binary.LittleEndian.PutUint64(sh1[32:40], uint64(biSize)) // sh_size
	binary.LittleEndian.PutUint64(sh1[48:56], 16)             // sh_addralign (16-byte)
	// sh_entsize[56:64] stays 0 — no fixed-size entries

	// sh[2]: .shstrtab — SHT_STRTAB
	sh2 := out[shtOff+2*shdrsz:]
	binary.LittleEndian.PutUint32(sh2[0:4], 15)                    // sh_name = 15
	binary.LittleEndian.PutUint32(sh2[4:8], 3)                     // sh_type = SHT_STRTAB
	binary.LittleEndian.PutUint64(sh2[24:32], uint64(strtabOff))   // sh_offset
	binary.LittleEndian.PutUint64(sh2[32:40], uint64(len(strtab))) // sh_size
	binary.LittleEndian.PutUint64(sh2[48:56], 1)                   // sh_addralign

	// Patch ELF header (64 bytes at the start of out).
	binary.LittleEndian.PutUint64(out[40:48], uint64(shtOff)) // e_shoff
	binary.LittleEndian.PutUint16(out[58:60], shdrsz)          // e_shentsize
	binary.LittleEndian.PutUint16(out[60:62], 3)               // e_shnum
	binary.LittleEndian.PutUint16(out[62:64], 2)               // e_shstrndx

	return out
}

// buildMinimalELF writes a 64-byte Elf64_Ehdr followed by one
// Phdr (sized 56 bytes) so parseELFHeaders reaches the rejection
// path matching the scenario. Defaults select a valid ELF64 LE
// x86_64 ET_EXEC with one PT_LOAD segment and no body.
//
// When WithGoBuildInfo is set the builder appends the buildinfo
// blob after the program-header region and adds a proper ELF
// section header table (null + .go.buildinfo + .shstrtab).
// debug/buildinfo.DataStart() uses the .go.buildinfo section
// name; the section-header approach mirrors what the real linker
// emits and is the only path that works reliably in Go ≥ 1.26.
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
	if o.WithNeeded {
		phnum++
	}
	totalSize := ehdrSize + int(phnum)*phdrSize
	dynOff := totalSize // where the dynamic section body lives
	if o.WithDynamic {
		totalSize += 16 // 16-byte DT_NULL entry
	}
	if o.WithNeeded {
		totalSize += 32 // DT_NEEDED(8+8) + DT_NULL(8+8)
	}

	// When WithGoBuildInfo is set we reserve aligned space for the
	// blob. The section-header table is appended after the slice is
	// fully populated (see appendSectionHeaders call below).
	var biOff int
	var biBlob []byte
	if o.WithGoBuildInfo {
		biBlob = buildInfoBlob()
		if rem := totalSize % 16; rem != 0 {
			totalSize += 16 - rem // align biOff to 16 bytes
		}
		biOff = totalSize
		totalSize += len(biBlob)
		// saferio.ReadDataAt returns (n, io.EOF) when a read exactly
		// exhausts a SectionReader, which debug/buildinfo treats as
		// errNotGoExe. Pad by MaxVarintLen64 (10) bytes so every
		// DataReader call within the blob range has >10 bytes remaining,
		// preventing all boundary-EOF conditions during string decoding.
		totalSize += binary.MaxVarintLen64
	}

	// When WithDynamic or WithGoBuildInfo is used, the first PT_LOAD
	// must cover the whole program-header + data region so every
	// mapped offset is reachable. The section-header table sits
	// outside the PT_LOAD (debug/buildinfo reads it via elf.NewFile,
	// not via program headers), so totalSize here is the size before
	// appendSectionHeaders extends the slice.
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
	// rejection path). When WithDynamic or WithGoBuildInfo is set,
	// this PT_LOAD covers the entire body region so every mapped
	// offset is reachable by mapAndRelocateELF.
	off := ehdrSize
	pType := uint32(1)
	if o.NoLoad {
		pType = 4 // PT_NOTE — trips the "no PT_LOAD" guard
	}
	binary.LittleEndian.PutUint32(out[off:off+4], pType)
	binary.LittleEndian.PutUint32(out[off+4:off+8], 5) // PF_R | PF_X
	if o.WithDynamic || o.WithNeeded || o.WithGoBuildInfo {
		// PT_LOAD: offset=0, vaddr=0, filesz=memsz=totalSize.
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
		binary.LittleEndian.PutUint32(out[off:off+4], 2)   // PT_DYNAMIC
		binary.LittleEndian.PutUint32(out[off+4:off+8], 6) // PF_R | PF_W
		binary.LittleEndian.PutUint64(out[off+8:off+16], uint64(dynOff))  // p_offset
		binary.LittleEndian.PutUint64(out[off+16:off+24], uint64(dynOff)) // p_vaddr
		binary.LittleEndian.PutUint64(out[off+24:off+32], uint64(dynOff)) // p_paddr
		binary.LittleEndian.PutUint64(out[off+32:off+40], 16)             // p_filesz (just DT_NULL)
		binary.LittleEndian.PutUint64(out[off+40:off+48], 16)             // p_memsz
		binary.LittleEndian.PutUint64(out[off+48:off+56], 8)              // p_align
		// out[dynOff..dynOff+16] stays zero — that's exactly DT_NULL,
		// which terminates the dynamic walk before any DT_RELA.
		off += phdrSize
	}
	if o.WithNeeded {
		// PT_DYNAMIC phdr pointing at the 32-byte body: DT_NEEDED + DT_NULL.
		binary.LittleEndian.PutUint32(out[off:off+4], 2)   // PT_DYNAMIC
		binary.LittleEndian.PutUint32(out[off+4:off+8], 6) // PF_R | PF_W
		binary.LittleEndian.PutUint64(out[off+8:off+16], uint64(dynOff))  // p_offset
		binary.LittleEndian.PutUint64(out[off+16:off+24], uint64(dynOff)) // p_vaddr
		binary.LittleEndian.PutUint64(out[off+24:off+32], uint64(dynOff)) // p_paddr
		binary.LittleEndian.PutUint64(out[off+32:off+40], 32)             // p_filesz
		binary.LittleEndian.PutUint64(out[off+40:off+48], 32)             // p_memsz
		binary.LittleEndian.PutUint64(out[off+48:off+56], 8)              // p_align
		// Dynamic section body: one DT_NEEDED(tag=1, val=0) then DT_NULL.
		binary.LittleEndian.PutUint64(out[dynOff:dynOff+8], 1)    // DT_NEEDED tag
		binary.LittleEndian.PutUint64(out[dynOff+8:dynOff+16], 0) // d_val (irrelevant)
		// out[dynOff+16..dynOff+32] stays zero — DT_NULL sentinel.
		off += phdrSize
	}
	_ = off // no more phdr branches after this point

	if o.WithGoBuildInfo {
		// Write the blob into the already-allocated biOff slot.
		copy(out[biOff:], biBlob)
		// Append section header table so debug/buildinfo.DataStart()
		// finds .go.buildinfo by name (the PT_LOAD fallback is
		// unreliable in Go ≥ 1.26 without section headers).
		out = appendSectionHeaders(out, biOff, len(biBlob))
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
