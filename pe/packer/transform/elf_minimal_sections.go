package transform

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Section-headered minimal ELF — companion to [BuildMinimalELF64].
// Where the Brian-Raiter-style writer in elf_minimal.go produces the
// smallest possible runnable ELF (no SHT), this variant adds a real
// Section Header Table with a ".text" section so that PlanELF /
// debug/elf can chew on it.
//
// Why both flavours coexist:
//
//   - BuildMinimalELF64 (Raiter): 120 B headers + code, no SHT.
//     Right when the result is the FINAL artifact (operator wraps a
//     bundle and ships). Smallest possible footprint.
//   - BuildMinimalELF64WithSections (this file): adds ~280 B for the
//     SHT + shstrtab. Right when the result will be FED INTO PackBinary
//     for UPX-style in-place encryption — PlanELF needs a parseable
//     `.text` section to compute encrypted bounds.
//
// Layout (file offsets):
//
//	[0..63]    Ehdr
//	[64..119]  Phdr 0 — PT_LOAD covering [0..codeEnd-1], RWX
//	[120..175] Phdr 1 — reserved zero-filled slot (e_phnum = 1, kernel
//	           ignores; InjectStubELF promotes to PT_LOAD R+X for stub)
//	[176..N-1] code bytes  (N = 176 + len(code))
//	[N..]      Section header table (3 entries × 64 = 192 B)
//	           1. SHT_NULL
//	           2. .text   (SHT_PROGBITS, SHF_ALLOC|EXECINSTR|WRITE)
//	           3. .shstrtab (SHT_STRTAB)
//	[N+192..]  shstrtab pool: "\0.text\0.shstrtab\0" (17 B)
//
// PT_LOAD covers only [0..codeEnd-1] in memory — the SHT + shstrtab
// live past p_filesz and are kernel-invisible. The kernel jumps to
// e_entry = vaddr + 176, debug/elf walks the SHT to find `.text`,
// PackBinary's InjectStubELF writes a second PT_LOAD into the
// reserved slot at file offset 120.

const (
	// elfMinSectReservedPhdrs is the count of zero-filled phdr slots we
	// pre-reserve after the active phdr table. InjectStubELF needs at
	// least 1 free slot to append its stub PT_LOAD; we reserve 1 — the
	// minimal sufficient amount.
	elfMinSectReservedPhdrs = 1
	elfMinSectActivePhdrs   = 1 // the kernel-visible PT_LOAD covering code
	elfMinSectHeadersSize   = 64 + (elfMinSectActivePhdrs+elfMinSectReservedPhdrs)*56
	elfShdrSize             = 64
	elfMinSectSHTEntries    = 3 // NULL + .text + .shstrtab
)

// shstrtabPool is the constant string pool the SHT references.
//
//	offset 0:  "\0"           (NULL section)
//	offset 1:  ".text\0"      (offsets 1..6)
//	offset 7:  ".shstrtab\0"  (offsets 7..16)
var shstrtabPool = []byte("\x00.text\x00.shstrtab\x00")

// ErrMinimalELFWithSectionsCodeEmpty fires on nil/empty code.
var ErrMinimalELFWithSectionsCodeEmpty = errors.New("transform: minimal ELF (with sections) requires non-empty code")

// BuildMinimalELF64WithSections builds a runnable ELF64 ET_EXEC with
// a real Section Header Table — fed-into-PackBinary-friendly. Same
// vaddr default + same RWX PT_LOAD as [BuildMinimalELF64], plus the
// SHT + shstrtab tail required for PlanELF / debug/elf.
//
// Vaddr defaults to [MinimalELF64Vaddr] (0x400000). Pass a per-build
// secret-derived value to defeat 'tiny ELF at standard ld base' yara.
func BuildMinimalELF64WithSections(code []byte) ([]byte, error) {
	return BuildMinimalELF64WithSectionsAndVaddr(code, MinimalELF64Vaddr)
}

// BuildMinimalELF64WithSectionsAndVaddr is the per-build-tunable variant.
//
// Validates page-alignment + kernel-half on vaddr like the no-sections
// counterpart.
func BuildMinimalELF64WithSectionsAndVaddr(code []byte, vaddr uint64) ([]byte, error) {
	if len(code) == 0 {
		return nil, ErrMinimalELFWithSectionsCodeEmpty
	}
	if vaddr == 0 {
		vaddr = MinimalELF64Vaddr
	}
	if vaddr&0xfff != 0 {
		return nil, fmt.Errorf("transform: minimal ELF vaddr %#x not page-aligned", vaddr)
	}
	if vaddr >= 0x0000800000000000 {
		return nil, fmt.Errorf("transform: minimal ELF vaddr %#x in kernel half", vaddr)
	}

	const ehdrSize = 64
	const phdrSize = 56
	// Active phdr (1) + reserved slack for InjectStubELF (1).
	const headersSize = ehdrSize + (elfMinSectActivePhdrs+elfMinSectReservedPhdrs)*phdrSize
	codeOff := uint64(headersSize)
	codeEnd := codeOff + uint64(len(code))
	shtOff := codeEnd
	shtSize := uint64(elfMinSectSHTEntries * elfShdrSize)
	shstrOff := shtOff + shtSize
	shstrSize := uint64(len(shstrtabPool))
	totalSize := shstrOff + shstrSize

	out := make([]byte, totalSize)

	// === Ehdr ===
	copy(out[0:4], []byte{0x7f, 'E', 'L', 'F'})
	out[4] = 2 // ELFCLASS64
	out[5] = 1 // ELFDATA2LSB
	out[6] = 1 // EV_CURRENT
	out[7] = 0 // ELFOSABI_NONE
	binary.LittleEndian.PutUint16(out[0x10:], 2)              // ET_EXEC
	binary.LittleEndian.PutUint16(out[0x12:], 0x3e)           // EM_X86_64
	binary.LittleEndian.PutUint32(out[0x14:], 1)              // EV_CURRENT
	binary.LittleEndian.PutUint64(out[0x18:], vaddr+codeOff)  // e_entry — start of code
	binary.LittleEndian.PutUint64(out[0x20:], ehdrSize)       // e_phoff
	binary.LittleEndian.PutUint64(out[0x28:], shtOff)         // e_shoff
	binary.LittleEndian.PutUint32(out[0x30:], 0)              // e_flags
	binary.LittleEndian.PutUint16(out[0x34:], ehdrSize)       // e_ehsize
	binary.LittleEndian.PutUint16(out[0x36:], phdrSize)       // e_phentsize
	binary.LittleEndian.PutUint16(out[0x38:], 1)              // e_phnum
	binary.LittleEndian.PutUint16(out[0x3a:], elfShdrSize)    // e_shentsize
	binary.LittleEndian.PutUint16(out[0x3c:], elfMinSectSHTEntries) // e_shnum
	binary.LittleEndian.PutUint16(out[0x3e:], 2)              // e_shstrndx — index 2 (.shstrtab)

	// === Phdr (1 PT_LOAD covering [0..codeEnd-1] in memory) ===
	phdr := out[ehdrSize:]
	binary.LittleEndian.PutUint32(phdr[0x00:], 1)         // PT_LOAD
	binary.LittleEndian.PutUint32(phdr[0x04:], 7)         // PF_R | PF_W | PF_X
	binary.LittleEndian.PutUint64(phdr[0x08:], 0)         // p_offset
	binary.LittleEndian.PutUint64(phdr[0x10:], vaddr)     // p_vaddr
	binary.LittleEndian.PutUint64(phdr[0x18:], vaddr)     // p_paddr
	binary.LittleEndian.PutUint64(phdr[0x20:], codeEnd)   // p_filesz
	binary.LittleEndian.PutUint64(phdr[0x28:], codeEnd)   // p_memsz
	binary.LittleEndian.PutUint64(phdr[0x30:], 0x1000)    // p_align

	// === Code ===
	copy(out[codeOff:codeEnd], code)

	// === Section Header Table ===
	// Shdr layout (offsets):
	//   0x00 sh_name      u32
	//   0x04 sh_type      u32
	//   0x08 sh_flags     u64
	//   0x10 sh_addr      u64
	//   0x18 sh_offset    u64
	//   0x20 sh_size      u64
	//   0x28 sh_link      u32
	//   0x2c sh_info      u32
	//   0x30 sh_addralign u64
	//   0x38 sh_entsize   u64
	//
	// Entry 0: SHT_NULL — all zeros.

	// Entry 1: .text
	textShdr := out[shtOff+elfShdrSize:]
	binary.LittleEndian.PutUint32(textShdr[0x00:], 1)              // sh_name → ".text" at offset 1
	binary.LittleEndian.PutUint32(textShdr[0x04:], 1)              // SHT_PROGBITS
	binary.LittleEndian.PutUint64(textShdr[0x08:], 7)              // SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE
	binary.LittleEndian.PutUint64(textShdr[0x10:], vaddr+codeOff)  // sh_addr
	binary.LittleEndian.PutUint64(textShdr[0x18:], codeOff)        // sh_offset
	binary.LittleEndian.PutUint64(textShdr[0x20:], uint64(len(code))) // sh_size
	binary.LittleEndian.PutUint32(textShdr[0x28:], 0)              // sh_link
	binary.LittleEndian.PutUint32(textShdr[0x2c:], 0)              // sh_info
	binary.LittleEndian.PutUint64(textShdr[0x30:], 16)             // sh_addralign — 16 B
	binary.LittleEndian.PutUint64(textShdr[0x38:], 0)              // sh_entsize

	// Entry 2: .shstrtab
	strShdr := out[shtOff+2*elfShdrSize:]
	binary.LittleEndian.PutUint32(strShdr[0x00:], 7) // sh_name → ".shstrtab" at offset 7
	binary.LittleEndian.PutUint32(strShdr[0x04:], 3) // SHT_STRTAB
	binary.LittleEndian.PutUint64(strShdr[0x08:], 0)
	binary.LittleEndian.PutUint64(strShdr[0x10:], 0)
	binary.LittleEndian.PutUint64(strShdr[0x18:], shstrOff)
	binary.LittleEndian.PutUint64(strShdr[0x20:], shstrSize)
	binary.LittleEndian.PutUint32(strShdr[0x28:], 0)
	binary.LittleEndian.PutUint32(strShdr[0x2c:], 0)
	binary.LittleEndian.PutUint64(strShdr[0x30:], 1) // 1-byte aligned
	binary.LittleEndian.PutUint64(strShdr[0x38:], 0)

	// === shstrtab pool ===
	copy(out[shstrOff:totalSize], shstrtabPool)

	if err := validateMinimalELFWithSections(out, len(code), vaddr); err != nil {
		return nil, fmt.Errorf("transform: minimal ELF (with sections) self-check: %w", err)
	}
	return out, nil
}

// validateMinimalELFWithSections runs the layout invariants for the
// SHT-bearing variant. Catches off-by-ones at build time.
func validateMinimalELFWithSections(elf []byte, codeLen int, vaddr uint64) error {
	const ehdrSize = 64
	const phdrSize = 56
	const headersSize = ehdrSize + (elfMinSectActivePhdrs+elfMinSectReservedPhdrs)*phdrSize
	wantTotal := uint64(headersSize) + uint64(codeLen) +
		uint64(elfMinSectSHTEntries*elfShdrSize) + uint64(len(shstrtabPool))
	if uint64(len(elf)) != wantTotal {
		return fmt.Errorf("size %d != expected %d", len(elf), wantTotal)
	}
	if string(elf[0:4]) != "\x7fELF" {
		return fmt.Errorf("magic %q != ELF", elf[0:4])
	}
	if elf[4] != 2 || elf[5] != 1 {
		return fmt.Errorf("bad e_ident class/data: %d %d", elf[4], elf[5])
	}
	entry := binary.LittleEndian.Uint64(elf[0x18:])
	wantEntry := vaddr + headersSize
	if entry != wantEntry {
		return fmt.Errorf("e_entry %#x != %#x", entry, wantEntry)
	}
	shoff := binary.LittleEndian.Uint64(elf[0x28:])
	wantShoff := uint64(headersSize) + uint64(codeLen)
	if shoff != wantShoff {
		return fmt.Errorf("e_shoff %#x != %#x", shoff, wantShoff)
	}
	return nil
}
