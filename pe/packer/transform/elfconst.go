package transform

// ELF64 layout constants exported for sibling packages in
// pe/packer/ that share PHT manipulation logic. Values come from
// the System V ABI AMD64 Rev 1.0 spec; the unexported
// near-duplicates inside elf.go remain for in-package brevity.
//
// Keep this set deliberately small — the cover layer only needs
// header sizes, page size, the PT_LOAD type, and a flag plus the
// phdr field offsets it writes. New consumers should add only the
// fields they actually read or write rather than mirroring every
// constant in elf.go.
const (
	// ElfEhdrSize is the byte length of the Elf64_Ehdr (e_phoff
	// lookup, magic-byte gates).
	ElfEhdrSize = 64

	// ElfPhdrSize is the byte length of one Elf64_Phdr entry.
	ElfPhdrSize = 56

	// ElfPageSize is the canonical x86-64 page size, used for
	// PT_LOAD vaddr / file-offset alignment.
	ElfPageSize uint64 = 0x1000

	// ElfEhdrPhoffOffset is the file offset of e_phoff inside the
	// Ehdr.
	ElfEhdrPhoffOffset = 0x20

	// ElfEhdrPhentszOffset is the file offset of e_phentsize.
	ElfEhdrPhentszOffset = 0x36

	// ElfEhdrPhnumOffset is the file offset of e_phnum.
	ElfEhdrPhnumOffset = 0x38

	// ElfPhdrTypeOffset is p_type (offset 0 inside a phdr entry).
	ElfPhdrTypeOffset = 0x00

	// ElfPhdrFlagsOffset is p_flags.
	ElfPhdrFlagsOffset = 0x04

	// ElfPhdrOffsetOffset is p_offset (file offset of segment).
	ElfPhdrOffsetOffset = 0x08

	// ElfPhdrVAddrOffset is p_vaddr (virtual address of segment).
	ElfPhdrVAddrOffset = 0x10

	// ElfPhdrPAddrOffset is p_paddr.
	ElfPhdrPAddrOffset = 0x18

	// ElfPhdrFileSzOffset is p_filesz.
	ElfPhdrFileSzOffset = 0x20

	// ElfPhdrMemSzOffset is p_memsz.
	ElfPhdrMemSzOffset = 0x28

	// ElfPhdrAlignOffset is p_align.
	ElfPhdrAlignOffset = 0x30

	// ElfPFR is PF_R — read permission flag in p_flags.
	ElfPFR uint32 = 4

	// ElfPFW is PF_W — write permission flag.
	ElfPFW uint32 = 2

	// ElfPFX is PF_X — execute permission flag.
	ElfPFX uint32 = 1

	// ElfPTLoad is PT_LOAD — loadable-segment type.
	ElfPTLoad uint32 = 1
)
