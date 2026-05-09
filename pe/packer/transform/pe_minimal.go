package transform

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Minimal PE32+ writer — companion to elf_minimal.go's
// BuildMinimalELF64. Where elf.go ATTACHES new sections to an
// existing input PE, this file BUILDS a fresh PE32+ from scratch
// around a caller-supplied byte slice that gets treated as the
// binary's complete code+data region.
//
// Used by the Windows symmetric path of the all-asm bundle wrap
// (see [docs/superpowers/plans/2026-05-09-windows-tiny-exe.md]).
//
// Layout (canonical, ~336 bytes header overhead):
//
//	[DOS header (64 B)]
//	[PE signature "PE\0\0" (4 B)]
//	[COFF header (20 B)]
//	[Optional header PE32+ (240 B)]
//	[Section header × 1 (40 B)]
//	[code]
//
// The single section is RWX (R+W+X characteristics) covering the
// whole code+bundle region — same RWX trade-off as the Linux all-asm
// path: loud on EDRs but appropriate for a self-modifying decrypt
// stub.

// MinimalPE32PlusImageBase is the canonical 64-bit Windows ImageBase
// (`0x140000000`) — what `link.exe /MACHINE:X64` defaults to for
// EXEs and what every standard Windows binary lands at when ASLR is
// disabled. Operators wanting to randomise this per build pass a
// custom value to [BuildMinimalPE32PlusWithBase] (typically derived
// from the operator secret via [github.com/oioio-space/maldev/pe/packer.BundleProfile.Vaddr]).
const MinimalPE32PlusImageBase uint64 = 0x140000000

// MinimalPE32PlusHeadersSize is the byte count consumed by the DOS
// header + PE signature + COFF + Optional header + 1 section
// header. Code begins at this offset in the produced file AND at
// ImageBase + this offset in memory.
const MinimalPE32PlusHeadersSize = 64 + 4 + 20 + 240 + 40

// ErrMinimalPECodeEmpty fires when [BuildMinimalPE32Plus] is called
// with nil / zero-length code.
var ErrMinimalPECodeEmpty = errors.New("transform: minimal PE requires non-empty code")

// BuildMinimalPE32Plus returns a runnable Windows PE32+ EXE that maps
// `code` at [MinimalPE32PlusImageBase + MinimalPE32PlusHeadersSize, …)
// and sets the entry point to the start of `code`.
//
// Single section, R+W+X — analogous to the Linux minimal-ELF wrap.
// Operators wanting a conventional R+X / R+W section split should
// use the section-aware path in transform/pe.go::InjectStubPE
// instead.
//
// Returns the PE bytes. Nothing is written to disk; caller decides
// where the bytes go.
func BuildMinimalPE32Plus(code []byte) ([]byte, error) {
	return BuildMinimalPE32PlusWithBase(code, MinimalPE32PlusImageBase)
}

// BuildMinimalPE32PlusWithBase is the per-build-tunable variant of
// [BuildMinimalPE32Plus]. The PE's `ImageBase` field lands at
// `imageBase` instead of the canonical `0x140000000`, randomising
// one more yara-able byte pattern. imageBase MUST be 64 KiB-aligned
// (Windows's SectionAlignment is 4 KiB but ImageBase alignment is
// 64 KiB per the PE spec). Zero falls back to the canonical default.
//
// Picking imageBase from the operator's per-deployment secret (see
// pe/packer.DeriveBundleProfile) makes every shipped binary land at
// a different address, defeating yara rules keyed on
// "single-section-RWX PE at ImageBase 0x140000000".
func BuildMinimalPE32PlusWithBase(code []byte, imageBase uint64) ([]byte, error) {
	if len(code) == 0 {
		return nil, ErrMinimalPECodeEmpty
	}
	if imageBase == 0 {
		imageBase = MinimalPE32PlusImageBase
	}
	if imageBase&0xffff != 0 {
		return nil, fmt.Errorf("transform: minimal PE imageBase %#x not 64 KiB-aligned", imageBase)
	}
	// Windows refuses ImageBase values that overlap kernel-half
	// (0xffff8000_00000000 and up) or NULL.
	if imageBase >= 0xffff800000000000 {
		return nil, fmt.Errorf("transform: minimal PE imageBase %#x in kernel half", imageBase)
	}

	const dosSize = 64
	const peSigSize = 4
	const coffSize = 20
	const optSize = 240
	const secSize = 40
	const headersSize = dosSize + peSigSize + coffSize + optSize + secSize

	const sectionAlignment uint32 = 0x1000 // 4 KiB
	const fileAlignment uint32 = 0x200     // 512 B

	// SizeOfImage = section virtual size + headers, rounded up to
	// SectionAlignment (4 KiB).
	codeSize := uint32(len(code))
	sectionVA := alignUpU32(uint32(headersSize), sectionAlignment)
	sizeOfImage := alignUpU32(sectionVA+codeSize, sectionAlignment)
	sizeOfHeaders := alignUpU32(uint32(headersSize), fileAlignment)
	sectionFileOff := sizeOfHeaders
	totalFileSize := sectionFileOff + alignUpU32(codeSize, fileAlignment)

	out := make([]byte, totalFileSize)

	// === DOS header (64 B) ===
	// Only e_magic (offset 0, "MZ") and e_lfanew (offset 0x3c,
	// pointer to PE signature) are consulted by the Windows loader.
	// Everything in between is legacy and can be zero.
	copy(out[0:2], []byte{'M', 'Z'})
	binary.LittleEndian.PutUint32(out[0x3c:0x40], uint32(dosSize))

	// === PE signature ===
	peSigOff := uint32(dosSize)
	copy(out[peSigOff:peSigOff+4], []byte{'P', 'E', 0, 0})

	// === COFF header (20 B) ===
	coffOff := peSigOff + 4
	binary.LittleEndian.PutUint16(out[coffOff:coffOff+2], 0x8664)            // Machine = IMAGE_FILE_MACHINE_AMD64
	binary.LittleEndian.PutUint16(out[coffOff+2:coffOff+4], 1)                // NumberOfSections
	binary.LittleEndian.PutUint32(out[coffOff+4:coffOff+8], 0)                // TimeDateStamp (op-secret-derivable later)
	binary.LittleEndian.PutUint32(out[coffOff+8:coffOff+12], 0)               // PointerToSymbolTable
	binary.LittleEndian.PutUint32(out[coffOff+12:coffOff+16], 0)              // NumberOfSymbols
	binary.LittleEndian.PutUint16(out[coffOff+16:coffOff+18], optSize)        // SizeOfOptionalHeader
	// Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
	binary.LittleEndian.PutUint16(out[coffOff+18:coffOff+20], 0x0022)

	// === Optional header PE32+ (240 B) ===
	optOff := coffOff + 20
	binary.LittleEndian.PutUint16(out[optOff:optOff+2], 0x020b) // Magic = PE32+
	out[optOff+2] = 14                                          // MajorLinkerVersion
	out[optOff+3] = 0                                           // MinorLinkerVersion
	binary.LittleEndian.PutUint32(out[optOff+4:optOff+8], alignUpU32(codeSize, fileAlignment))   // SizeOfCode
	binary.LittleEndian.PutUint32(out[optOff+8:optOff+12], 0)                                    // SizeOfInitializedData
	binary.LittleEndian.PutUint32(out[optOff+12:optOff+16], 0)                                   // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(out[optOff+16:optOff+20], sectionVA)                           // AddressOfEntryPoint
	binary.LittleEndian.PutUint32(out[optOff+20:optOff+24], sectionVA)                           // BaseOfCode
	binary.LittleEndian.PutUint64(out[optOff+24:optOff+32], imageBase)                           // ImageBase
	binary.LittleEndian.PutUint32(out[optOff+32:optOff+36], sectionAlignment)                    // SectionAlignment
	binary.LittleEndian.PutUint32(out[optOff+36:optOff+40], fileAlignment)                       // FileAlignment
	binary.LittleEndian.PutUint16(out[optOff+40:optOff+42], 6)                                   // MajorOSVersion
	binary.LittleEndian.PutUint16(out[optOff+42:optOff+44], 0)                                   // MinorOSVersion
	binary.LittleEndian.PutUint16(out[optOff+44:optOff+46], 0)                                   // MajorImageVersion
	binary.LittleEndian.PutUint16(out[optOff+46:optOff+48], 0)                                   // MinorImageVersion
	binary.LittleEndian.PutUint16(out[optOff+48:optOff+50], 6)                                   // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(out[optOff+50:optOff+52], 0)                                   // MinorSubsystemVersion
	binary.LittleEndian.PutUint32(out[optOff+52:optOff+56], 0)                                   // Win32VersionValue (reserved)
	binary.LittleEndian.PutUint32(out[optOff+56:optOff+60], sizeOfImage)                         // SizeOfImage
	binary.LittleEndian.PutUint32(out[optOff+60:optOff+64], sizeOfHeaders)                       // SizeOfHeaders
	binary.LittleEndian.PutUint32(out[optOff+64:optOff+68], 0)                                   // CheckSum (loader doesn't verify for EXEs)
	binary.LittleEndian.PutUint16(out[optOff+68:optOff+70], 3)                                   // Subsystem = WINDOWS_CUI (console)
	binary.LittleEndian.PutUint16(out[optOff+70:optOff+72], 0x8160)                              // DllCharacteristics: HIGH_ENTROPY_VA | DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
	binary.LittleEndian.PutUint64(out[optOff+72:optOff+80], 0x100000)                            // SizeOfStackReserve (1 MiB)
	binary.LittleEndian.PutUint64(out[optOff+80:optOff+88], 0x1000)                              // SizeOfStackCommit
	binary.LittleEndian.PutUint64(out[optOff+88:optOff+96], 0x100000)                            // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(out[optOff+96:optOff+104], 0x1000)                             // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(out[optOff+104:optOff+108], 0)                                 // LoaderFlags (reserved)
	binary.LittleEndian.PutUint32(out[optOff+108:optOff+112], 16)                                // NumberOfRvaAndSizes
	// DataDirectories [16 × 8 B] left zero — no imports / exports / resources / etc.

	// === Section header × 1 (.text, 40 B) ===
	secOff := optOff + optSize
	copy(out[secOff:secOff+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(out[secOff+8:secOff+12], codeSize)                             // VirtualSize
	binary.LittleEndian.PutUint32(out[secOff+12:secOff+16], sectionVA)                           // VirtualAddress
	binary.LittleEndian.PutUint32(out[secOff+16:secOff+20], alignUpU32(codeSize, fileAlignment)) // SizeOfRawData
	binary.LittleEndian.PutUint32(out[secOff+20:secOff+24], sectionFileOff)                      // PointerToRawData
	binary.LittleEndian.PutUint32(out[secOff+24:secOff+28], 0)                                   // PointerToRelocations
	binary.LittleEndian.PutUint32(out[secOff+28:secOff+32], 0)                                   // PointerToLineNumbers
	binary.LittleEndian.PutUint16(out[secOff+32:secOff+34], 0)                                   // NumberOfRelocations
	binary.LittleEndian.PutUint16(out[secOff+34:secOff+36], 0)                                   // NumberOfLineNumbers
	// Characteristics: CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE
	binary.LittleEndian.PutUint32(out[secOff+36:secOff+40], 0xe0000020)

	// === Code at sectionFileOff ===
	copy(out[sectionFileOff:sectionFileOff+codeSize], code)

	if err := validateMinimalPE(out, len(code), imageBase); err != nil {
		return nil, fmt.Errorf("transform: minimal PE self-check: %w", err)
	}
	return out, nil
}

// validateMinimalPE runs the structural invariants the Windows
// loader will enforce on load. Catches off-by-ones at build time
// instead of at exec time.
func validateMinimalPE(pe []byte, codeLen int, imageBase uint64) error {
	if len(pe) < MinimalPE32PlusHeadersSize {
		return fmt.Errorf("size %d < headers %d", len(pe), MinimalPE32PlusHeadersSize)
	}
	if pe[0] != 'M' || pe[1] != 'Z' {
		return fmt.Errorf("bad DOS magic: %q", pe[0:2])
	}
	lfanew := binary.LittleEndian.Uint32(pe[0x3c:0x40])
	if lfanew == 0 || int(lfanew)+4 > len(pe) {
		return fmt.Errorf("e_lfanew %#x out of range", lfanew)
	}
	if string(pe[lfanew:lfanew+4]) != "PE\x00\x00" {
		return fmt.Errorf("missing PE signature at %#x", lfanew)
	}
	machine := binary.LittleEndian.Uint16(pe[lfanew+4 : lfanew+6])
	if machine != 0x8664 {
		return fmt.Errorf("Machine = %#x, want 0x8664 (AMD64)", machine)
	}
	return nil
}

// alignUpU32 lives in pe.go — reuse from there.
