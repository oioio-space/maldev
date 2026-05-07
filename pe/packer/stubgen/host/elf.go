package host

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ELFConfig parameterizes EmitELF.
type ELFConfig struct {
	Stage1Bytes []byte // emitted asm — goes into the PT_LOAD code segment
	PayloadBlob []byte // encoded stage 2 || encrypted payload — goes into the PT_LOAD data segment
}

// Sentinels.
var (
	ErrEmptyStage1ELF  = errors.New("host: Stage1Bytes is empty (ELF)")
	ErrEmptyPayloadELF = errors.New("host: PayloadBlob is empty (ELF)")
)

// ELF64 layout constants (System V ABI AMD64 Rev 1.0).
const (
	elfMagic0      = 0x7F
	elfClass64     = 2
	elfDataLE      = 1
	elfVersion     = 1
	elfOSABISysv   = 0
	eTypeDyn       = 3
	eMachineX86_64 = 62

	ehdrSize    = 64
	phdrSizeELF = 56
	elfPageSize = 0x1000

	elfPF_X = 1
	elfPF_R = 4
	ptLoad  = 1
)

// EmitELF emits a 2-PT_LOAD static-PIE ELF64. PT_LOAD #1 (R+E)
// holds stage 1 asm; PT_LOAD #2 (R) holds the encoded payload
// blob. ET_DYN + no PT_DYNAMIC + no PT_INTERP — matches Phase 1f
// Stage E runtime gate.
//
// Layout: Ehdr (64) → 2 × Phdr (56 each, 112 total) → page-aligned
// PT_LOAD bodies. Section header table is omitted (sh_off=0,
// sh_num=0); ELF runtime loaders only need program headers.
func EmitELF(cfg ELFConfig) ([]byte, error) {
	if len(cfg.Stage1Bytes) == 0 {
		return nil, ErrEmptyStage1ELF
	}
	if len(cfg.PayloadBlob) == 0 {
		return nil, ErrEmptyPayloadELF
	}

	const phdrCount = 2
	const phdrTableEnd = ehdrSize + phdrCount*phdrSizeELF // 64 + 112 = 176

	// PT_LOAD #1 (text): page-aligned start after the header+phdrs.
	textOffset := alignUpELF(uint64(phdrTableEnd), elfPageSize)
	textVAddr := textOffset
	textFileSz := uint64(len(cfg.Stage1Bytes))
	textMemSz := textFileSz

	// PT_LOAD #2 (data): page-aligned start after the text segment.
	dataOffset := alignUpELF(textOffset+textFileSz, elfPageSize)
	dataVAddr := dataOffset
	dataFileSz := uint64(len(cfg.PayloadBlob))
	dataMemSz := dataFileSz

	totalSize := dataOffset + dataFileSz
	out := make([]byte, totalSize)

	// e_ident[16]
	out[0] = elfMagic0
	out[1] = 'E'
	out[2] = 'L'
	out[3] = 'F'
	out[4] = elfClass64
	out[5] = elfDataLE
	out[6] = elfVersion
	out[7] = elfOSABISysv

	// Ehdr non-ident fields
	binary.LittleEndian.PutUint16(out[16:18], eTypeDyn)
	binary.LittleEndian.PutUint16(out[18:20], eMachineX86_64)
	binary.LittleEndian.PutUint32(out[20:24], elfVersion)
	binary.LittleEndian.PutUint64(out[24:32], textVAddr) // e_entry → stage 1 start
	binary.LittleEndian.PutUint64(out[32:40], ehdrSize)  // e_phoff → right after Ehdr
	// e_shoff = 0, e_flags = 0 (offsets 40..52 stay zero — no section headers; x86_64 defines no flags)
	binary.LittleEndian.PutUint16(out[52:54], ehdrSize)
	binary.LittleEndian.PutUint16(out[54:56], phdrSizeELF)
	binary.LittleEndian.PutUint16(out[56:58], phdrCount)
	// e_shentsize / e_shnum / e_shstrndx = 0 (offsets 58..64 stay zero)

	// Phdr #1: PT_LOAD (R+E) — text
	writeProgHdr(out[ehdrSize:ehdrSize+phdrSizeELF],
		ptLoad, elfPF_R|elfPF_X,
		textOffset, textVAddr, textVAddr,
		textFileSz, textMemSz, elfPageSize)

	// Phdr #2: PT_LOAD (R) — data (encoded payload blob)
	writeProgHdr(out[ehdrSize+phdrSizeELF:ehdrSize+2*phdrSizeELF],
		ptLoad, elfPF_R,
		dataOffset, dataVAddr, dataVAddr,
		dataFileSz, dataMemSz, elfPageSize)

	copy(out[textOffset:], cfg.Stage1Bytes)
	copy(out[dataOffset:], cfg.PayloadBlob)

	return out, nil
}

// writeProgHdr emits one Elf64_Phdr (56 bytes) to dst. Field order
// matches the Elf64_Phdr struct: p_type, p_flags, p_offset, p_vaddr,
// p_paddr, p_filesz, p_memsz, p_align — note flags is at offset 4 in
// the 64-bit layout (different from 32-bit where it's at offset 24).
func writeProgHdr(dst []byte, pType uint32, pFlags uint32,
	pOffset, pVAddr, pPAddr, pFileSz, pMemSz, pAlign uint64) {
	if len(dst) < phdrSizeELF {
		panic(fmt.Sprintf("writeProgHdr: dst too small: %d", len(dst)))
	}
	binary.LittleEndian.PutUint32(dst[0:4], pType)
	binary.LittleEndian.PutUint32(dst[4:8], pFlags)
	binary.LittleEndian.PutUint64(dst[8:16], pOffset)
	binary.LittleEndian.PutUint64(dst[16:24], pVAddr)
	binary.LittleEndian.PutUint64(dst[24:32], pPAddr)
	binary.LittleEndian.PutUint64(dst[32:40], pFileSz)
	binary.LittleEndian.PutUint64(dst[40:48], pMemSz)
	binary.LittleEndian.PutUint64(dst[48:56], pAlign)
}

// alignUpELF rounds v up to the next multiple of align (uint64 variant
// for ELF offsets; pe.go's alignUp handles the PE uint32 case).
// align must be a power of two.
func alignUpELF(v, align uint64) uint64 {
	return (v + align - 1) &^ (align - 1)
}
