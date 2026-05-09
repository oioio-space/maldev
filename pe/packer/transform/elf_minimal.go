package transform

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Minimal ELF writer — companion to the in-place modification path
// shipped in elf.go. Where elf.go ATTACHES new sections + a stub
// segment to an existing input ELF, this file BUILDS a fresh ELF64
// from scratch around a caller-supplied byte slice that gets treated
// as the binary's complete code+data region.
//
// Used by the C6-P3 all-asm bundle stub path: an operator concatenates
// the stub asm + bundle blob and asks for an ELF wrapper that the
// kernel can load directly. No PT_INTERP, no dynamic linker, no
// imports — the wrapped bytes are self-contained position-dependent
// code with embedded data.
//
// The format mirrors Brian Raiter's "tiny ELF" trick (a 45-byte ELF
// is reachable; we add some headroom for a real entry-point offset).
// The Ehdr + Phdr + payload all live in the same PT_LOAD, mapped
// from file offset 0 to a chosen vaddr.

// MinimalELF64Vaddr is the virtual address the lone PT_LOAD lands at.
// 0x400000 is the canonical x86-64 ET_EXEC base (matches what `ld -static`
// emits by default), so the result looks unsuspicious in /proc/self/maps.
const MinimalELF64Vaddr uint64 = 0x400000

// MinimalELF64HeadersSize is the byte count consumed by the ELF
// header (64) plus a single program header (56). Code begins at this
// offset in the produced file AND at vaddr+this offset in memory.
const MinimalELF64HeadersSize = 64 + 56

// ErrMinimalELFCodeEmpty fires when [BuildMinimalELF64] is called with
// nil / zero-length code.
var ErrMinimalELFCodeEmpty = errors.New("transform: minimal ELF requires non-empty code")

// BuildMinimalELF64 returns a runnable ELF64 ET_EXEC binary that maps
// `code` at [MinimalELF64Vaddr + MinimalELF64HeadersSize, ...) and
// sets the entry point to the start of `code`.
//
// The result is RWX (PF_R | PF_W | PF_X) on the single PT_LOAD —
// loud on any EDR worth its salt, but appropriate for a self-modifying
// stub that decrypts payload bytes in place. Operators wanting a
// conventional R+X / R+W split should use the section-aware path in
// transform/elf.go::InjectStubELF instead.
//
// Returns the ELF bytes. Nothing is written to disk; caller decides
// where the bytes go.
func BuildMinimalELF64(code []byte) ([]byte, error) {
	if len(code) == 0 {
		return nil, ErrMinimalELFCodeEmpty
	}

	const ehdrSize = 64
	const phdrSize = 56
	const headersSize = ehdrSize + phdrSize
	totalSize := uint64(headersSize + len(code))
	entryVaddr := MinimalELF64Vaddr + uint64(headersSize)

	out := make([]byte, totalSize)

	// ELF64 Ehdr (offsets per System V ABI / elf.h):
	//   0x00 e_ident[16]
	//   0x10 e_type      u16
	//   0x12 e_machine   u16
	//   0x14 e_version   u32
	//   0x18 e_entry     u64
	//   0x20 e_phoff     u64
	//   0x28 e_shoff     u64
	//   0x30 e_flags     u32
	//   0x34 e_ehsize    u16
	//   0x36 e_phentsize u16
	//   0x38 e_phnum     u16
	//   0x3a e_shentsize u16
	//   0x3c e_shnum     u16
	//   0x3e e_shstrndx  u16
	copy(out[0:4], []byte{0x7f, 'E', 'L', 'F'})
	out[4] = 2 // EI_CLASS = ELFCLASS64
	out[5] = 1 // EI_DATA  = ELFDATA2LSB
	out[6] = 1 // EI_VERSION = EV_CURRENT
	out[7] = 0 // EI_OSABI  = ELFOSABI_NONE (System V)
	// e_ident[8:16] = padding, leave zero
	binary.LittleEndian.PutUint16(out[0x10:], 2)            // ET_EXEC
	binary.LittleEndian.PutUint16(out[0x12:], 0x3e)         // EM_X86_64
	binary.LittleEndian.PutUint32(out[0x14:], 1)            // EV_CURRENT
	binary.LittleEndian.PutUint64(out[0x18:], entryVaddr)   // e_entry
	binary.LittleEndian.PutUint64(out[0x20:], ehdrSize)     // e_phoff (PHT immediately after Ehdr)
	binary.LittleEndian.PutUint64(out[0x28:], 0)            // e_shoff = 0 (no SHT)
	binary.LittleEndian.PutUint32(out[0x30:], 0)            // e_flags
	binary.LittleEndian.PutUint16(out[0x34:], ehdrSize)     // e_ehsize
	binary.LittleEndian.PutUint16(out[0x36:], phdrSize)     // e_phentsize
	binary.LittleEndian.PutUint16(out[0x38:], 1)            // e_phnum
	binary.LittleEndian.PutUint16(out[0x3a:], 0)            // e_shentsize
	binary.LittleEndian.PutUint16(out[0x3c:], 0)            // e_shnum
	binary.LittleEndian.PutUint16(out[0x3e:], 0)            // e_shstrndx

	// ELF64 Phdr (single PT_LOAD covering the whole file):
	//   0x00 p_type   u32  = 1 (PT_LOAD)
	//   0x04 p_flags  u32  = 7 (PF_R | PF_W | PF_X)
	//   0x08 p_offset u64  = 0
	//   0x10 p_vaddr  u64
	//   0x18 p_paddr  u64
	//   0x20 p_filesz u64
	//   0x28 p_memsz  u64
	//   0x30 p_align  u64
	phdr := out[ehdrSize:]
	binary.LittleEndian.PutUint32(phdr[0x00:], 1)                  // PT_LOAD
	binary.LittleEndian.PutUint32(phdr[0x04:], 7)                  // RWX
	binary.LittleEndian.PutUint64(phdr[0x08:], 0)                  // p_offset
	binary.LittleEndian.PutUint64(phdr[0x10:], MinimalELF64Vaddr)  // p_vaddr
	binary.LittleEndian.PutUint64(phdr[0x18:], MinimalELF64Vaddr)  // p_paddr
	binary.LittleEndian.PutUint64(phdr[0x20:], totalSize)          // p_filesz
	binary.LittleEndian.PutUint64(phdr[0x28:], totalSize)          // p_memsz
	binary.LittleEndian.PutUint64(phdr[0x30:], 0x1000)             // p_align

	copy(out[headersSize:], code)

	if err := validateMinimalELF(out, len(code)); err != nil {
		return nil, fmt.Errorf("transform: minimal ELF self-check: %w", err)
	}
	return out, nil
}

// validateMinimalELF runs the structural invariants the kernel itself
// will check on load. Catches off-by-ones at build time instead of as
// SIGSEGVs at exec time.
func validateMinimalELF(elf []byte, codeLen int) error {
	const ehdrSize = 64
	const phdrSize = 56
	if len(elf) != ehdrSize+phdrSize+codeLen {
		return fmt.Errorf("size %d != ehdr+phdr+code (%d)", len(elf), ehdrSize+phdrSize+codeLen)
	}
	if string(elf[0:4]) != "\x7fELF" {
		return fmt.Errorf("magic %q != ELF", elf[0:4])
	}
	if elf[4] != 2 || elf[5] != 1 {
		return fmt.Errorf("bad e_ident class/data: %d %d", elf[4], elf[5])
	}
	entry := binary.LittleEndian.Uint64(elf[0x18:])
	wantEntry := MinimalELF64Vaddr + ehdrSize + phdrSize
	if entry != wantEntry {
		return fmt.Errorf("e_entry %#x != %#x", entry, wantEntry)
	}
	return nil
}
