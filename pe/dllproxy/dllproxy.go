package dllproxy

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// Machine identifies the COFF machine type baked into the emitted PE.
type Machine uint16

const (
	// MachineAMD64 emits a PE32+ x86-64 DLL. Default and only Phase 1 target.
	MachineAMD64 Machine = pe.IMAGE_FILE_MACHINE_AMD64
	// MachineI386 is reserved for Phase 3 — 32-bit support.
	MachineI386 Machine = pe.IMAGE_FILE_MACHINE_I386
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

// PE / COFF / Optional-Header constants used by the emitter. Anything
// stdlib `debug/pe` exposes is referenced through that package; only
// the few it omits ship as locals.
const (
	dosMagic    = 0x5A4D     // "MZ"
	peSignature = 0x00004550 // "PE\0\0"

	imageFileCharacteristics   = pe.IMAGE_FILE_EXECUTABLE_IMAGE | pe.IMAGE_FILE_LARGE_ADDRESS_AWARE | pe.IMAGE_FILE_DLL
	imageDLLCharacteristicsNXC = pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
	imageRDataCharacteristics  = pe.IMAGE_SCN_CNT_INITIALIZED_DATA | pe.IMAGE_SCN_MEM_READ
	imageOptionalHdr64Magic    = 0x020B // not exposed by stdlib debug/pe
	imageNumberOfDirectoryRVAs = 16     // not exposed by stdlib debug/pe

	dosHeaderSize      = 64
	coffHeaderSize     = 20
	optionalHeader64Sz = 240
	sectionHeaderSize  = 40

	fileAlignment    = 0x200
	sectionAlignment = 0x1000
	imageBase64      = 0x180000000
)

// rdataRange records where the IMAGE_EXPORT_DIRECTORY lives inside the
// .rdata section. By design, the export directory spans the *entire*
// .rdata content (forwarder strings + name strings included) so that
// every forwarder RVA falls inside the data-directory range — that's
// the loader-side rule for forwarder detection. Hence dirRVA + dirSize
// also describe the section's full virtual extent.
type rdataRange struct {
	dirRVA  uint32
	dirSize uint32
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

	out = append(out, stringsBuf.Bytes()...)

	return out, rdataRange{dirRVA: sectionVA, dirSize: uint32(len(out))}, nil
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
// returns the final PE image. Headers are written through stdlib
// [debug/pe] structs so on-disk layout matches the spec without any
// hand-counted offsets.
func assemblePE(rdata []byte, r rdataRange, machine Machine) []byte {
	const peHeaderOffset = dosHeaderSize // e_lfanew = 0x40

	headersEnd := uint32(peHeaderOffset + 4 + coffHeaderSize + optionalHeader64Sz + sectionHeaderSize)
	sizeOfHeaders := alignUp(headersEnd, fileAlignment)
	rdataFileSize := alignUp(uint32(len(rdata)), fileAlignment)
	rdataVA := uint32(sectionAlignment)
	imageSize := alignUp(rdataVA+r.dirSize, sectionAlignment)

	coff := pe.FileHeader{
		Machine:              uint16(machine),
		NumberOfSections:     1,
		SizeOfOptionalHeader: optionalHeader64Sz,
		Characteristics:      imageFileCharacteristics,
	}
	opt := pe.OptionalHeader64{
		Magic:                       imageOptionalHdr64Magic,
		MajorLinkerVersion:          14,
		SizeOfInitializedData:       r.dirSize,
		ImageBase:                   imageBase64,
		SectionAlignment:            sectionAlignment,
		FileAlignment:               fileAlignment,
		MajorOperatingSystemVersion: 6,
		MajorSubsystemVersion:       6,
		SizeOfImage:                 imageSize,
		SizeOfHeaders:               sizeOfHeaders,
		Subsystem:                   pe.IMAGE_SUBSYSTEM_WINDOWS_GUI,
		DllCharacteristics:          imageDLLCharacteristicsNXC,
		SizeOfStackReserve:          0x100000,
		SizeOfStackCommit:           0x1000,
		SizeOfHeapReserve:           0x100000,
		SizeOfHeapCommit:            0x1000,
		NumberOfRvaAndSizes:         imageNumberOfDirectoryRVAs,
	}
	opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT] = pe.DataDirectory{
		VirtualAddress: r.dirRVA,
		Size:           r.dirSize,
	}
	sec := pe.SectionHeader32{
		Name:             [8]uint8{'.', 'r', 'd', 'a', 't', 'a'},
		VirtualSize:      r.dirSize,
		VirtualAddress:   rdataVA,
		SizeOfRawData:    rdataFileSize,
		PointerToRawData: sizeOfHeaders,
		Characteristics:  imageRDataCharacteristics,
	}

	// Encode headers into the leading sizeOfHeaders bytes.
	hdr := bytes.NewBuffer(make([]byte, 0, sizeOfHeaders))
	hdr.Write(make([]byte, peHeaderOffset)) // DOS header zero-pad — overwritten below
	binary.Write(hdr, binary.LittleEndian, uint32(peSignature))
	binary.Write(hdr, binary.LittleEndian, &coff)
	binary.Write(hdr, binary.LittleEndian, &opt)
	binary.Write(hdr, binary.LittleEndian, &sec)

	out := make([]byte, sizeOfHeaders+rdataFileSize)
	copy(out, hdr.Bytes())

	// DOS header — only the two fields the loader actually reads.
	binary.LittleEndian.PutUint16(out[0:], dosMagic)
	binary.LittleEndian.PutUint32(out[0x3c:], peHeaderOffset)

	// Section data follows the header block; trailing pad bytes stay
	// zero from the make() above.
	copy(out[sizeOfHeaders:], rdata)
	return out
}

// alignUp rounds n up to the nearest multiple of align (which must be
// a power of two — fileAlignment and sectionAlignment satisfy that).
func alignUp(n, align uint32) uint32 {
	return (n + align - 1) &^ (align - 1)
}
