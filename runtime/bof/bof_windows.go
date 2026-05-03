//go:build windows

package bof

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// COFF machine type for x64.
const machineAMD64 = 0x8664

// COFF relocation types for x64. Reference:
// https://learn.microsoft.com/windows/win32/debug/pe-format#type-indicators
const (
	imageRelAMD64Absolute = 0x0000
	imageRelAMD64Addr64   = 0x0001
	imageRelAMD64Addr32   = 0x0002
	imageRelAMD64Addr32NB = 0x0003
	imageRelAMD64Rel32     = 0x0004
	imageRelAMD64Rel32Plus1 = 0x0005
	imageRelAMD64Rel32Plus2 = 0x0006
	imageRelAMD64Rel32Plus3 = 0x0007
	imageRelAMD64Rel32Plus4 = 0x0008
	imageRelAMD64Rel32Plus5 = 0x0009
)

// coffHeader is the 20-byte COFF file header.
type coffHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// coffSection is a 40-byte COFF section header.
type coffSection struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

// coffRelocation is a 10-byte COFF relocation entry.
type coffRelocation struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// coffSymbol is an 18-byte COFF symbol table entry.
type coffSymbol struct {
	Name               [8]byte
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       byte
	NumberOfAuxSymbols byte
}

const coffHeaderSize = 20
const coffSectionSize = 40
const coffSymbolSize = 18
const coffRelocationSize = 10

// BOF represents a parsed Beacon Object File.
type BOF struct {
	Data  []byte
	Entry string // entry point function name (default: "go")

	// output buffers anything BeaconPrintf / BeaconOutput emit during
	// Execute. nil until Execute initialises it; Execute returns its
	// snapshot. Tests can also read the buffer directly via OutputBytes.
	output *beaconOutput

	// errors buffers anything BeaconErrorD / DD / NA emit during
	// Execute. Kept separate from output so callers can route the two
	// to different sinks; read via Errors().
	errors *beaconOutput

	// argBuf is the raw user args passed to Execute. BeaconDataParse
	// produces a parser cursor over this slice.
	argBuf []byte

	// spawnTo is the path BeaconGetSpawnTo returns to the BOF — the
	// fork-and-run target. Empty string by default; set per-BOF via
	// SetSpawnTo. The pinned []byte form (with trailing NUL) lives in
	// spawnToCStr so the address handed to native code stays stable.
	spawnTo     string
	spawnToCStr []byte
}

// SetSpawnTo configures the path BeaconGetSpawnTo returns when the BOF
// asks the loader for a fork-and-run target. Empty string (the default)
// means "no spawn target" — BOFs that consult BeaconGetSpawnTo see an
// empty C string and typically fall back to their own logic. Path is
// converted to a NUL-terminated byte slice once and pinned for the
// remaining lifetime of the BOF instance, so the address stays stable
// across Beacon API callbacks.
func (b *BOF) SetSpawnTo(path string) {
	b.spawnTo = path
	if path == "" {
		b.spawnToCStr = nil
		return
	}
	b.spawnToCStr = append([]byte(path), 0)
}

// Errors returns whatever the BOF emitted via BeaconErrorD / DD / NA
// during the last Execute. Returns nil before the first Execute call.
// The slice is a fresh copy — safe to retain after subsequent Execute
// calls clear the underlying buffer.
func (b *BOF) Errors() []byte {
	if b.errors == nil {
		return nil
	}
	return b.errors.Bytes()
}

// Load parses a COFF object file from bytes.
func Load(data []byte) (*BOF, error) {
	if len(data) < coffHeaderSize {
		return nil, fmt.Errorf("invalid COFF: data too small")
	}

	hdr := parseCOFFHeader(data)
	if hdr.Machine != machineAMD64 {
		return nil, fmt.Errorf("unsupported COFF machine type: 0x%X", hdr.Machine)
	}

	// Basic validation: section table must fit.
	sectionTableEnd := coffHeaderSize + int(hdr.SizeOfOptionalHeader) + int(hdr.NumberOfSections)*coffSectionSize
	if sectionTableEnd > len(data) {
		return nil, fmt.Errorf("invalid COFF: truncated section table")
	}

	return &BOF{
		Data:  data,
		Entry: "go",
	}, nil
}

// Execute runs the BOF's entry point with the given arguments.
// The BOF is loaded into executable memory, relocations applied,
// and the entry function is called. Anything the BOF emits via
// BeaconPrintf / BeaconOutput is captured and returned as the
// first result.
//
// Concurrency: BOF execution is serialised package-wide (the
// Beacon API stubs read a single currentBOF pointer guarded by
// bofMu). Concurrent Execute calls block on each other.
func (b *BOF) Execute(args []byte) ([]byte, error) {
	if len(b.Data) < coffHeaderSize {
		return nil, fmt.Errorf("invalid COFF: data too small")
	}

	b.output = newBeaconOutput()
	b.errors = newBeaconOutput()
	b.argBuf = args

	bofMu.Lock()
	currentBOF = b
	defer func() {
		currentBOF = nil
		bofMu.Unlock()
	}()

	hdr := parseCOFFHeader(b.Data)

	// 1. Parse sections.
	sections := make([]coffSection, hdr.NumberOfSections)
	sectionOff := coffHeaderSize + int(hdr.SizeOfOptionalHeader)
	for i := range sections {
		off := sectionOff + i*coffSectionSize
		sections[i] = parseCOFFSection(b.Data[off:])
	}

	// 2. Find .text section.
	textIdx := -1
	for i, sec := range sections {
		name := sectionName(sec.Name)
		if name == ".text" {
			textIdx = i
			break
		}
	}
	if textIdx < 0 {
		return nil, fmt.Errorf(".text section not found")
	}

	textSec := sections[textIdx]

	// 3. Lay out every section that has raw data into a single
	//    contiguous VirtualAlloc page. Section indices in the COFF are
	//    1-based; sectionBase[idx] holds the absolute address of each
	//    loaded section. Sections without raw data (.bss et al.) get
	//    no allocation and won't be referenced by relocations that
	//    matter for in-process execution.
	sectionBase := make(map[int]uintptr, len(sections))
	type loaded struct {
		idx    int
		offset int
		data   []byte
	}
	var laid []loaded
	cursor := 0
	for i, sec := range sections {
		if sec.SizeOfRawData == 0 || sec.PointerToRawData == 0 {
			continue
		}
		end := int(sec.PointerToRawData) + int(sec.SizeOfRawData)
		if end > len(b.Data) {
			return nil, fmt.Errorf("invalid COFF: section %d data out of bounds", i+1)
		}
		laid = append(laid, loaded{
			idx:    i + 1,
			offset: cursor,
			data:   b.Data[sec.PointerToRawData:end],
		})
		cursor += int(sec.SizeOfRawData)
	}

	// 4. Pre-scan relocations to enumerate unique external symbols.
	//    Each gets an 8-byte import-table slot at the tail of the
	//    allocation; slot addresses stay within ±2 GB of every
	//    section so REL32 displacements always reach.
	imports, err := b.collectImports(textSec, hdr)
	if err != nil {
		return nil, err
	}

	loadedLen := cursor
	importTableLen := len(imports) * 8
	totalLen := loadedLen + importTableLen
	if totalLen == 0 {
		return nil, fmt.Errorf("BOF has no loadable sections")
	}

	execMem, err := windows.VirtualAlloc(
		0,
		uintptr(totalLen),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return nil, fmt.Errorf("executable memory allocation failed: %w", err)
	}
	defer windows.VirtualFree(execMem, 0, windows.MEM_RELEASE)

	dst := unsafe.Slice((*byte)(unsafe.Pointer(execMem)), totalLen)
	for _, l := range laid {
		copy(dst[l.offset:l.offset+len(l.data)], l.data)
		sectionBase[l.idx] = execMem + uintptr(l.offset)
	}

	// 5. Resolve each external symbol and write its function address
	//    into the corresponding import-table slot.
	importSlots := make(map[string]uintptr, len(imports))
	for i, name := range imports {
		addr, ok := resolveBeaconImport(name)
		if !ok {
			return nil, fmt.Errorf("unresolved external symbol %q", name)
		}
		slotAddr := execMem + uintptr(loadedLen+i*8)
		*(*uintptr)(unsafe.Pointer(slotAddr)) = addr
		importSlots[name] = slotAddr
	}

	// 6. Apply relocations for .text. In-section symbols resolve via
	//    sectionBase[sym.SectionNumber]; externals consult importSlots.
	textBase, ok := sectionBase[textIdx+1]
	if !ok {
		return nil, fmt.Errorf(".text section had no raw data")
	}
	textInMem := unsafe.Slice((*byte)(unsafe.Pointer(textBase)), int(textSec.SizeOfRawData))
	if textSec.NumberOfRelocations > 0 {
		if err := b.applyRelocations(textInMem, textBase, sectionBase, textSec, hdr, importSlots); err != nil {
			return nil, fmt.Errorf("relocation failed: %w", err)
		}
	}

	// 7. Find entry point symbol within .text.
	entryOffset, err := b.findSymbolOffset(hdr, textIdx)
	if err != nil {
		return nil, err
	}

	// 8. Call entry function with BOF convention: go(char *data, int len).
	entryAddr := textBase + uintptr(entryOffset)
	var argPtr, argLen uintptr
	if len(args) > 0 {
		argPtr = uintptr(unsafe.Pointer(&args[0]))
		argLen = uintptr(len(args))
	}
	fn := func() {
		syscallN(entryAddr, argPtr, argLen)
	}
	fn()

	return b.output.Bytes(), nil
}

// syscallN is a thin wrapper around windows.NewCallback-style calling.
// We use the raw syscall approach to call into the BOF entry.
func syscallN(addr uintptr, args ...uintptr) {
	switch len(args) {
	case 0:
		syscall.Syscall(addr, 0, 0, 0, 0)
	case 1:
		syscall.Syscall(addr, 1, args[0], 0, 0)
	case 2:
		syscall.Syscall(addr, 2, args[0], args[1], 0)
	default:
		syscall.Syscall(addr, uintptr(len(args)), args[0], args[1], args[2])
	}
}

// collectImports walks the .text section's relocation entries and returns
// the deduplicated list of external symbol names, preserving first-seen
// order so the import-table layout is deterministic. Each unique name
// gets one 8-byte slot at the tail of the BOF's executable allocation.
func (b *BOF) collectImports(textSec coffSection, hdr coffHeader) ([]string, error) {
	stringTableOff := int(hdr.PointerToSymbolTable) + int(hdr.NumberOfSymbols)*coffSymbolSize
	relocOff := int(textSec.PointerToRelocations)
	seen := map[string]struct{}{}
	var names []string
	for i := 0; i < int(textSec.NumberOfRelocations); i++ {
		off := relocOff + i*coffRelocationSize
		if off+coffRelocationSize > len(b.Data) {
			return nil, fmt.Errorf("relocation entry out of bounds")
		}
		reloc := parseCOFFRelocation(b.Data[off:])
		symOff := int(hdr.PointerToSymbolTable) + int(reloc.SymbolTableIndex)*coffSymbolSize
		if symOff+coffSymbolSize > len(b.Data) {
			return nil, fmt.Errorf("symbol table entry out of bounds")
		}
		sym := parseCOFFSymbol(b.Data[symOff:])
		if sym.SectionNumber != 0 {
			continue
		}
		name := symbolName(sym.Name, b.Data, stringTableOff)
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names, nil
}

// applyRelocations processes COFF relocations for the .text section.
// sectionBase maps a COFF (1-based) section index to the loaded base
// address of that section in execMem. importSlots maps each external
// symbol name to the absolute address of its import-table slot —
// co-allocated by Execute inside the same VirtualAlloc page as the
// code so REL32 reaches every target.
func (b *BOF) applyRelocations(textMem []byte, textBase uintptr, sectionBase map[int]uintptr, textSec coffSection, hdr coffHeader, importSlots map[string]uintptr) error {
	stringTableOff := int(hdr.PointerToSymbolTable) + int(hdr.NumberOfSymbols)*coffSymbolSize
	relocOff := int(textSec.PointerToRelocations)
	for i := 0; i < int(textSec.NumberOfRelocations); i++ {
		off := relocOff + i*coffRelocationSize
		if off+coffRelocationSize > len(b.Data) {
			return fmt.Errorf("relocation entry out of bounds")
		}
		reloc := parseCOFFRelocation(b.Data[off:])

		if int(reloc.VirtualAddress) >= len(textMem) {
			return fmt.Errorf("relocation target out of bounds")
		}

		// Resolve symbol value.
		symOff := int(hdr.PointerToSymbolTable) + int(reloc.SymbolTableIndex)*coffSymbolSize
		if symOff+coffSymbolSize > len(b.Data) {
			return fmt.Errorf("symbol table entry out of bounds")
		}
		sym := parseCOFFSymbol(b.Data[symOff:])

		// Target address resolution:
		//   - sym.SectionNumber > 0:  resolve to the loaded base of that
		//     section + sym.Value. Cross-section refs (.text → .rdata
		//     for string literals, .text → .data for globals) work
		//     because every section with raw data is mapped into the
		//     same VirtualAlloc.
		//   - sym.SectionNumber == 0:  external import. Look up the
		//     symbol name in importSlots; the relocation patches in the
		//     slot's address (BOF dereferences via mov reg, [rip+disp32]).
		var targetAddr uintptr
		if sym.SectionNumber > 0 {
			base, ok := sectionBase[int(sym.SectionNumber)]
			if !ok {
				return fmt.Errorf("relocation %d targets unmapped section %d", i, sym.SectionNumber)
			}
			targetAddr = base + uintptr(sym.Value)
		} else {
			name := symbolName(sym.Name, b.Data, stringTableOff)
			slotAddr, ok := importSlots[name]
			if !ok {
				return fmt.Errorf("unresolved external symbol %q at relocation %d", name, i)
			}
			targetAddr = slotAddr
		}

		patchAddr := reloc.VirtualAddress
		switch reloc.Type {
		case imageRelAMD64Absolute:
			// No-op: emitted as padding, the patch field is left as-is.

		case imageRelAMD64Addr64:
			if int(patchAddr)+8 > len(textMem) {
				return fmt.Errorf("ADDR64 patch out of bounds")
			}
			binary.LittleEndian.PutUint64(textMem[patchAddr:], uint64(targetAddr))

		case imageRelAMD64Addr32:
			if int(patchAddr)+4 > len(textMem) {
				return fmt.Errorf("ADDR32 patch out of bounds")
			}
			// 32-bit absolute address. Fails (silently truncates the high
			// 32 bits) when targetAddr doesn't fit in 32 bits, which is the
			// common case on x86-64 where system DLLs map above 4G. Emit a
			// loud error rather than corrupt the BOF code.
			if targetAddr>>32 != 0 {
				return fmt.Errorf("ADDR32 target 0x%X exceeds 32-bit range", targetAddr)
			}
			binary.LittleEndian.PutUint32(textMem[patchAddr:], uint32(targetAddr))

		case imageRelAMD64Addr32NB:
			if int(patchAddr)+4 > len(textMem) {
				return fmt.Errorf("ADDR32NB patch out of bounds")
			}
			// Image-base relative 32-bit address.
			rva := uint32(targetAddr - textBase)
			binary.LittleEndian.PutUint32(textMem[patchAddr:], rva)

		case imageRelAMD64Rel32,
			imageRelAMD64Rel32Plus1,
			imageRelAMD64Rel32Plus2,
			imageRelAMD64Rel32Plus3,
			imageRelAMD64Rel32Plus4,
			imageRelAMD64Rel32Plus5:
			if int(patchAddr)+4 > len(textMem) {
				return fmt.Errorf("REL32 patch out of bounds")
			}
			// RIP-relative: target - (patchLocation + 4 + bias).
			// REL32_N variants encode an implicit +N byte offset for
			// instructions where the displacement field is followed by
			// N more bytes before the next instruction (immediate
			// operands, prefixes). Bias = type - 0x0004.
			//
			// Critical: the original 4 displacement bytes encode an
			// addend — the offset INTO the target section/symbol that
			// the BOF wants. For section-symbol relocations
			// (e.g. .rdata strings) the addend selects which string
			// inside the section the lea/mov resolves to. We MUST add
			// the existing addend to targetAddr before computing the
			// new displacement, otherwise every .rdata reference
			// resolves to the section's first byte regardless of the
			// originally intended offset.
			addend := int32(binary.LittleEndian.Uint32(textMem[patchAddr:]))
			bias := int64(reloc.Type - imageRelAMD64Rel32)
			patchLocation := textBase + uintptr(patchAddr)
			rel := int64(targetAddr) + int64(addend) - int64(patchLocation+4) - bias
			binary.LittleEndian.PutUint32(textMem[patchAddr:], uint32(int32(rel)))

		default:
			return fmt.Errorf("unsupported relocation type: 0x%X", reloc.Type)
		}
	}
	return nil
}

// findSymbolOffset locates the entry point symbol and returns its offset
// within the .text section.
func (b *BOF) findSymbolOffset(hdr coffHeader, textSectionIdx int) (uint32, error) {
	// String table starts right after the symbol table.
	stringTableOff := int(hdr.PointerToSymbolTable) + int(hdr.NumberOfSymbols)*coffSymbolSize

	for i := uint32(0); i < hdr.NumberOfSymbols; i++ {
		symOff := int(hdr.PointerToSymbolTable) + int(i)*coffSymbolSize
		if symOff+coffSymbolSize > len(b.Data) {
			break
		}
		sym := parseCOFFSymbol(b.Data[symOff:])

		name := symbolName(sym.Name, b.Data, stringTableOff)

		// BOF entry points may be prefixed with underscore on some toolchains.
		if name == b.Entry || name == "_"+b.Entry {
			// Verify the symbol is in the .text section.
			// COFF section numbers are 1-based.
			if int(sym.SectionNumber) != textSectionIdx+1 {
				continue
			}
			return sym.Value, nil
		}

		// Skip auxiliary symbols.
		i += uint32(sym.NumberOfAuxSymbols)
	}

	return 0, fmt.Errorf("entry point symbol %q not found", b.Entry)
}

// parseCOFFHeader reads the COFF header from the start of data.
func parseCOFFHeader(data []byte) coffHeader {
	return coffHeader{
		Machine:              binary.LittleEndian.Uint16(data[0:]),
		NumberOfSections:     binary.LittleEndian.Uint16(data[2:]),
		TimeDateStamp:        binary.LittleEndian.Uint32(data[4:]),
		PointerToSymbolTable: binary.LittleEndian.Uint32(data[8:]),
		NumberOfSymbols:      binary.LittleEndian.Uint32(data[12:]),
		SizeOfOptionalHeader: binary.LittleEndian.Uint16(data[16:]),
		Characteristics:      binary.LittleEndian.Uint16(data[18:]),
	}
}

// parseCOFFSection reads a section header from data.
func parseCOFFSection(data []byte) coffSection {
	var sec coffSection
	copy(sec.Name[:], data[:8])
	sec.VirtualSize = binary.LittleEndian.Uint32(data[8:])
	sec.VirtualAddress = binary.LittleEndian.Uint32(data[12:])
	sec.SizeOfRawData = binary.LittleEndian.Uint32(data[16:])
	sec.PointerToRawData = binary.LittleEndian.Uint32(data[20:])
	sec.PointerToRelocations = binary.LittleEndian.Uint32(data[24:])
	sec.PointerToLineNumbers = binary.LittleEndian.Uint32(data[28:])
	sec.NumberOfRelocations = binary.LittleEndian.Uint16(data[32:])
	sec.NumberOfLineNumbers = binary.LittleEndian.Uint16(data[34:])
	sec.Characteristics = binary.LittleEndian.Uint32(data[36:])
	return sec
}

// parseCOFFRelocation reads a relocation entry from data.
func parseCOFFRelocation(data []byte) coffRelocation {
	return coffRelocation{
		VirtualAddress:   binary.LittleEndian.Uint32(data[0:]),
		SymbolTableIndex: binary.LittleEndian.Uint32(data[4:]),
		Type:             binary.LittleEndian.Uint16(data[8:]),
	}
}

// parseCOFFSymbol reads a symbol table entry from data.
func parseCOFFSymbol(data []byte) coffSymbol {
	var sym coffSymbol
	copy(sym.Name[:], data[:8])
	sym.Value = binary.LittleEndian.Uint32(data[8:])
	sym.SectionNumber = int16(binary.LittleEndian.Uint16(data[12:]))
	sym.Type = binary.LittleEndian.Uint16(data[14:])
	sym.StorageClass = data[16]
	sym.NumberOfAuxSymbols = data[17]
	return sym
}

// sectionName extracts a null-terminated section name.
func sectionName(raw [8]byte) string {
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i])
		}
	}
	return string(raw[:])
}

// symbolName resolves a COFF symbol name. If the first 4 bytes are zero,
// the remaining 4 bytes are an offset into the string table.
func symbolName(raw [8]byte, data []byte, stringTableOff int) string {
	// Short name: first 4 bytes are nonzero.
	if binary.LittleEndian.Uint32(raw[:4]) != 0 {
		for i, b := range raw {
			if b == 0 {
				return string(raw[:i])
			}
		}
		return string(raw[:])
	}

	// Long name: offset into string table.
	offset := binary.LittleEndian.Uint32(raw[4:8])
	start := stringTableOff + int(offset)
	if start >= len(data) {
		return ""
	}

	end := start
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[start:end])
}
