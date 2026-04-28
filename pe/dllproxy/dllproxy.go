package dllproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Machine identifies the COFF machine type baked into the emitted PE.
type Machine uint16

const (
	// MachineAMD64 emits a PE32+ x86-64 DLL. Default and only Phase 1 target.
	MachineAMD64 Machine = 0x8664
	// MachineI386 is reserved for Phase 3 — 32-bit support.
	MachineI386 Machine = 0x14c
)

// String returns the canonical COFF machine name.
func (m Machine) String() string {
	switch m {
	case MachineAMD64:
		return "AMD64"
	case MachineI386:
		return "I386"
	default:
		return fmt.Sprintf("Machine(0x%04x)", uint16(m))
	}
}

// PathScheme controls how forwarder strings address the legitimate target DLL.
type PathScheme int

const (
	// PathSchemeGlobalRoot uses `\\.\GLOBALROOT\SystemRoot\System32\<target>` —
	// the perfect-proxy trick from mrexodia. Default. Avoids self-recursion
	// even when the proxy DLL sits in System32 itself, and survives most
	// path-redirection schemes (KnownDLLs aside).
	PathSchemeGlobalRoot PathScheme = iota

	// PathSchemeSystem32 uses `C:\Windows\System32\<target>`. Simpler to
	// read, but recurses into self if deployed at System32 — only safe for
	// hijack opportunities outside System32 (almost all real ones).
	PathSchemeSystem32
)

// String returns a human-readable scheme name.
func (p PathScheme) String() string {
	switch p {
	case PathSchemeGlobalRoot:
		return "GlobalRoot"
	case PathSchemeSystem32:
		return "System32"
	default:
		return fmt.Sprintf("PathScheme(%d)", int(p))
	}
}

// Options tunes the emitter. The zero value is valid — defaults to
// MachineAMD64 + PathSchemeGlobalRoot, no payload DLL.
type Options struct {
	// Machine selects the target architecture. Zero means MachineAMD64.
	Machine Machine

	// PathScheme selects how forwarder strings address the target.
	// Zero means PathSchemeGlobalRoot.
	PathScheme PathScheme

	// PayloadDLL — Phase 2 only. Filename of an additional DLL to
	// LoadLibraryA on DLL_PROCESS_ATTACH. Currently rejected with
	// [ErrPayloadUnsupported] until the DllMain emitter lands.
	PayloadDLL string
}

// Sentinel errors callers may inspect with errors.Is.
var (
	// ErrEmptyExports is returned when no exports are supplied — a DLL
	// with an empty export table is technically legal but useless as a
	// forwarder, and almost always indicates a caller bug.
	ErrEmptyExports = errors.New("dllproxy: at least one export required")
	// ErrEmptyTargetName is returned when targetName is blank.
	ErrEmptyTargetName = errors.New("dllproxy: target name required")
	// ErrI386NotSupported is returned for MachineI386 — Phase 3 work.
	ErrI386NotSupported = errors.New("dllproxy: MachineI386 not yet implemented (phase 3)")
	// ErrPayloadUnsupported is returned when Options.PayloadDLL is set —
	// Phase 2 work.
	ErrPayloadUnsupported = errors.New("dllproxy: PayloadDLL not yet implemented (phase 2)")
)

// Generate emits a Windows DLL byte stream proxying targetName's named
// exports back to the legitimate target. The result is a complete PE
// image ready to be written to disk and dropped at a hijack location.
//
// The emitter validates inputs, sorts exports alphabetically (Windows
// loader requires it for the binary search by name), and produces a
// minimal forwarder-only PE: a single .rdata section holding the
// export directory + forwarder strings, no .text, no DllMain, entry
// point zero. Windows accepts this layout per the PE spec — the
// loader simply skips the absent DllMain on DLL_PROCESS_ATTACH.
//
// On any input error a sentinel from the package's Err* set is
// returned — wrap with errors.Is to switch on cause.
func Generate(targetName string, exports []string, opts Options) ([]byte, error) {
	if targetName == "" {
		return nil, ErrEmptyTargetName
	}
	if len(exports) == 0 {
		return nil, ErrEmptyExports
	}
	if opts.Machine == 0 {
		opts.Machine = MachineAMD64
	}
	if opts.Machine != MachineAMD64 {
		return nil, fmt.Errorf("%w: got %s", ErrI386NotSupported, opts.Machine)
	}
	if opts.PayloadDLL != "" {
		return nil, ErrPayloadUnsupported
	}

	sortedExports := make([]string, len(exports))
	copy(sortedExports, exports)
	sort.Strings(sortedExports)

	rdata, edirRange, err := buildRData(targetName, sortedExports, opts.PathScheme)
	if err != nil {
		return nil, fmt.Errorf("dllproxy: build .rdata: %w", err)
	}
	return assemblePE(rdata, edirRange, opts.Machine), nil
}

// PE / COFF / Optional-Header constants used by the emitter.
const (
	dosMagic    = 0x5A4D     // "MZ"
	peSignature = 0x00004550 // "PE\0\0"

	imageFileDLL               = 0x2000
	imageFileExecutable        = 0x0002
	imageFileLargeAddressAware = 0x0020
	imageFileCharacteristics   = imageFileExecutable | imageFileLargeAddressAware | imageFileDLL
	imageDLLCharacteristicsNXC = 0x0100 // NX_COMPAT
	imageSubsystemWindowsGUI   = 2
	imageOptionalHdr64Magic    = 0x020B
	imageScnCntInitializedData = 0x00000040
	imageScnMemRead            = 0x40000000
	imageRDataCharacteristics  = imageScnCntInitializedData | imageScnMemRead
	imageDirectoryEntryExport  = 0
	imageNumberOfDirectoryRVAs = 16

	dosHeaderSize       = 64
	coffHeaderSize      = 20
	optionalHeader64Sz  = 240
	sectionHeaderSize   = 40
	dataDirectoryEntrySz = 8

	fileAlignment    = 0x200
	sectionAlignment = 0x1000
	imageBase64      = 0x180000000
)

// rdataRange records the file-relative offsets and resulting RVAs of the
// IMAGE_EXPORT_DIRECTORY data, used to populate the optional-header
// data directory entry [0].
type rdataRange struct {
	exportDirRVA  uint32
	exportDirSize uint32
	virtualSize   uint32
}

// buildRData produces the in-memory layout of the proxy DLL's single
// .rdata section: export directory header, function/name/ordinal
// arrays, DLL name, forwarder strings, and export name strings.
//
// All RVAs are computed relative to a section base of sectionAlignment
// (0x1000), which matches the layout the assembler stamps into the
// section header further down.
func buildRData(targetName string, sortedExports []string, scheme PathScheme) ([]byte, rdataRange, error) {
	const sectionVA = sectionAlignment // first (and only) section sits at RVA 0x1000

	n := uint32(len(sortedExports))
	const exportDirSz = 40

	addrFuncsOffset := uint32(exportDirSz)              // immediately after the directory struct
	addrNamesOffset := addrFuncsOffset + 4*n            // uint32 per function
	addrOrdsOffset := addrNamesOffset + 4*n             // uint32 per name
	stringsOffset := addrOrdsOffset + 2*n               // uint16 per ordinal

	// Strings table layout (concatenated, NUL-terminated):
	//   1. DLL name ("<targetName>\0")
	//   2. forwarder string per export (sorted order)
	//   3. export name per export (sorted order)
	// Items 2 and 3 are interleaved per-export so we keep one loop.
	dllNameRVA := sectionVA + stringsOffset
	dllNameBytes := append([]byte(targetName), 0)
	cursor := stringsOffset + uint32(len(dllNameBytes))

	prefix := forwarderPrefix(scheme, targetName)

	forwarderRVAs := make([]uint32, n)
	exportNameRVAs := make([]uint32, n)
	var stringsBuf bytes.Buffer
	stringsBuf.Write(dllNameBytes)

	for i, name := range sortedExports {
		fwd := prefix + name
		forwarderRVAs[i] = sectionVA + cursor
		stringsBuf.WriteString(fwd)
		stringsBuf.WriteByte(0)
		cursor += uint32(len(fwd) + 1)

		exportNameRVAs[i] = sectionVA + cursor
		stringsBuf.WriteString(name)
		stringsBuf.WriteByte(0)
		cursor += uint32(len(name) + 1)
	}

	// Now assemble the .rdata buffer.
	out := make([]byte, stringsOffset)

	// IMAGE_EXPORT_DIRECTORY
	binary.LittleEndian.PutUint32(out[0:], 0)                                // Characteristics
	binary.LittleEndian.PutUint32(out[4:], 0)                                // TimeDateStamp
	binary.LittleEndian.PutUint16(out[8:], 0)                                // MajorVersion
	binary.LittleEndian.PutUint16(out[10:], 0)                               // MinorVersion
	binary.LittleEndian.PutUint32(out[12:], dllNameRVA)                      // Name (RVA to dll name string)
	binary.LittleEndian.PutUint32(out[16:], 1)                               // Base (ordinal 1 .. N)
	binary.LittleEndian.PutUint32(out[20:], n)                               // NumberOfFunctions
	binary.LittleEndian.PutUint32(out[24:], n)                               // NumberOfNames
	binary.LittleEndian.PutUint32(out[28:], sectionVA+addrFuncsOffset)       // AddressOfFunctions
	binary.LittleEndian.PutUint32(out[32:], sectionVA+addrNamesOffset)       // AddressOfNames
	binary.LittleEndian.PutUint32(out[36:], sectionVA+addrOrdsOffset)        // AddressOfNameOrdinals

	// AddressOfFunctions: forwarder RVAs (forwarder iff RVA falls inside
	// the export directory data range, which we ensure by choosing the
	// export-table data-directory size to span the entire .rdata content).
	for i, rva := range forwarderRVAs {
		binary.LittleEndian.PutUint32(out[addrFuncsOffset+uint32(i)*4:], rva)
	}
	for i, rva := range exportNameRVAs {
		binary.LittleEndian.PutUint32(out[addrNamesOffset+uint32(i)*4:], rva)
	}
	// AddressOfNameOrdinals — identity map since we sorted both names
	// and forwarder slots into the same alphabetic order.
	for i := uint32(0); i < n; i++ {
		binary.LittleEndian.PutUint16(out[addrOrdsOffset+i*2:], uint16(i))
	}

	// Append the strings table.
	out = append(out, stringsBuf.Bytes()...)

	r := rdataRange{
		exportDirRVA:  sectionVA, // export directory begins at start of .rdata
		exportDirSize: uint32(len(out)),
		virtualSize:   uint32(len(out)),
	}
	return out, r, nil
}

// forwarderPrefix returns the constant prefix prepended to each export
// name to form the absolute path forwarder string.
func forwarderPrefix(scheme PathScheme, targetName string) string {
	switch scheme {
	case PathSchemeSystem32:
		return `C:\Windows\System32\` + targetName + "."
	default: // PathSchemeGlobalRoot
		return `\\.\GLOBALROOT\SystemRoot\System32\` + targetName + "."
	}
}

// assemblePE stamps the headers around the supplied .rdata content and
// returns the final PE image.
func assemblePE(rdata []byte, r rdataRange, machine Machine) []byte {
	const peHeaderOffset = dosHeaderSize // e_lfanew = 0x40
	headersEnd := uint32(peHeaderOffset + 4 + coffHeaderSize + optionalHeader64Sz + sectionHeaderSize)
	sizeOfHeaders := alignUp(headersEnd, fileAlignment)

	rdataFileSize := alignUp(uint32(len(rdata)), fileAlignment)
	rdataVirtualSize := r.virtualSize
	rdataVirtualAddress := uint32(sectionAlignment)

	imageSize := alignUp(rdataVirtualAddress+rdataVirtualSize, sectionAlignment)

	out := make([]byte, sizeOfHeaders+rdataFileSize)

	// DOS header — only the fields the loader checks.
	binary.LittleEndian.PutUint16(out[0:], dosMagic)
	binary.LittleEndian.PutUint32(out[0x3c:], peHeaderOffset)

	// PE signature
	binary.LittleEndian.PutUint32(out[peHeaderOffset:], peSignature)

	coffOff := peHeaderOffset + 4
	// COFF header
	binary.LittleEndian.PutUint16(out[coffOff:], uint16(machine))
	binary.LittleEndian.PutUint16(out[coffOff+2:], 1) // NumberOfSections
	binary.LittleEndian.PutUint32(out[coffOff+4:], 0) // TimeDateStamp
	binary.LittleEndian.PutUint32(out[coffOff+8:], 0) // PointerToSymbolTable
	binary.LittleEndian.PutUint32(out[coffOff+12:], 0) // NumberOfSymbols
	binary.LittleEndian.PutUint16(out[coffOff+16:], optionalHeader64Sz)
	binary.LittleEndian.PutUint16(out[coffOff+18:], imageFileCharacteristics)

	// Optional header (PE32+)
	optOff := coffOff + coffHeaderSize
	binary.LittleEndian.PutUint16(out[optOff+0:], imageOptionalHdr64Magic)
	out[optOff+2] = 14 // MajorLinkerVersion
	out[optOff+3] = 0  // MinorLinkerVersion
	binary.LittleEndian.PutUint32(out[optOff+4:], 0)                  // SizeOfCode
	binary.LittleEndian.PutUint32(out[optOff+8:], rdataVirtualSize)   // SizeOfInitializedData
	binary.LittleEndian.PutUint32(out[optOff+12:], 0)                 // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(out[optOff+16:], 0)                 // AddressOfEntryPoint = 0 (no DllMain)
	binary.LittleEndian.PutUint32(out[optOff+20:], 0)                 // BaseOfCode
	binary.LittleEndian.PutUint64(out[optOff+24:], imageBase64)       // ImageBase (PE32+: uint64)
	binary.LittleEndian.PutUint32(out[optOff+32:], sectionAlignment)  // SectionAlignment
	binary.LittleEndian.PutUint32(out[optOff+36:], fileAlignment)     // FileAlignment
	binary.LittleEndian.PutUint16(out[optOff+40:], 6)                 // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(out[optOff+42:], 0)                 // MinorOperatingSystemVersion
	binary.LittleEndian.PutUint16(out[optOff+44:], 0)                 // MajorImageVersion
	binary.LittleEndian.PutUint16(out[optOff+46:], 0)                 // MinorImageVersion
	binary.LittleEndian.PutUint16(out[optOff+48:], 6)                 // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(out[optOff+50:], 0)                 // MinorSubsystemVersion
	binary.LittleEndian.PutUint32(out[optOff+52:], 0)                 // Win32VersionValue (reserved)
	binary.LittleEndian.PutUint32(out[optOff+56:], imageSize)         // SizeOfImage
	binary.LittleEndian.PutUint32(out[optOff+60:], sizeOfHeaders)     // SizeOfHeaders
	binary.LittleEndian.PutUint32(out[optOff+64:], 0)                 // CheckSum (Windows tolerates 0 for unsigned DLLs)
	binary.LittleEndian.PutUint16(out[optOff+68:], imageSubsystemWindowsGUI)
	binary.LittleEndian.PutUint16(out[optOff+70:], imageDLLCharacteristicsNXC)
	binary.LittleEndian.PutUint64(out[optOff+72:], 0x100000)          // SizeOfStackReserve
	binary.LittleEndian.PutUint64(out[optOff+80:], 0x1000)            // SizeOfStackCommit
	binary.LittleEndian.PutUint64(out[optOff+88:], 0x100000)          // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(out[optOff+96:], 0x1000)            // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(out[optOff+104:], 0)                // LoaderFlags
	binary.LittleEndian.PutUint32(out[optOff+108:], imageNumberOfDirectoryRVAs)

	// DataDirectory[16] — only entry [0] (Export) is populated.
	dataDirOff := optOff + 112
	binary.LittleEndian.PutUint32(out[dataDirOff+imageDirectoryEntryExport*dataDirectoryEntrySz:], r.exportDirRVA)
	binary.LittleEndian.PutUint32(out[dataDirOff+imageDirectoryEntryExport*dataDirectoryEntrySz+4:], r.exportDirSize)

	// Section header — single ".rdata" entry.
	secOff := optOff + optionalHeader64Sz
	copy(out[secOff:secOff+8], []byte(".rdata\x00\x00"))
	binary.LittleEndian.PutUint32(out[secOff+8:], rdataVirtualSize)
	binary.LittleEndian.PutUint32(out[secOff+12:], rdataVirtualAddress)
	binary.LittleEndian.PutUint32(out[secOff+16:], rdataFileSize)
	binary.LittleEndian.PutUint32(out[secOff+20:], sizeOfHeaders) // PointerToRawData
	binary.LittleEndian.PutUint32(out[secOff+24:], 0)             // PointerToRelocations
	binary.LittleEndian.PutUint32(out[secOff+28:], 0)             // PointerToLinenumbers
	binary.LittleEndian.PutUint16(out[secOff+32:], 0)             // NumberOfRelocations
	binary.LittleEndian.PutUint16(out[secOff+34:], 0)             // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(out[secOff+36:], imageRDataCharacteristics)

	// Section data — copy .rdata bytes at PointerToRawData; trailing
	// space already zero from make().
	copy(out[sizeOfHeaders:], rdata)

	return out
}

// alignUp rounds n up to the nearest multiple of align (which must be
// a power of two — fileAlignment and sectionAlignment satisfy that).
func alignUp(n, align uint32) uint32 {
	return (n + align - 1) &^ (align - 1)
}
