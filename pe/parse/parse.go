package parse

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
)

// File represents a parsed PE file with read/write capabilities.
type File struct {
	PE   *pe.File
	Raw  []byte
	Path string
}

// Open opens and parses a PE file.
func Open(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return FromBytes(raw, path)
}

// FromBytes parses a PE from raw bytes.
func FromBytes(data []byte, name string) (*File, error) {
	pf, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}
	return &File{PE: pf, Raw: data, Path: name}, nil
}

// Close releases resources.
func (f *File) Close() error {
	return f.PE.Close()
}

// Is64Bit returns true if the PE is a 64-bit binary.
func (f *File) Is64Bit() bool {
	_, ok := f.PE.OptionalHeader.(*pe.OptionalHeader64)
	return ok
}

// IsDLL returns true if the PE has the DLL characteristic flag.
func (f *File) IsDLL() bool {
	return f.PE.Characteristics&pe.IMAGE_FILE_DLL != 0
}

// ImageBase returns the preferred load address.
func (f *File) ImageBase() uint64 {
	switch oh := f.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return oh.ImageBase
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	}
	return 0
}

// EntryPoint returns the RVA of the entry point.
func (f *File) EntryPoint() uint32 {
	switch oh := f.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		return oh.AddressOfEntryPoint
	case *pe.OptionalHeader32:
		return oh.AddressOfEntryPoint
	}
	return 0
}

// Sections returns all section headers.
func (f *File) Sections() []*pe.Section {
	return f.PE.Sections
}

// SectionByName finds a section by name.
func (f *File) SectionByName(name string) *pe.Section {
	for _, sec := range f.PE.Sections {
		if sec.Name == name {
			return sec
		}
	}
	return nil
}

// SectionData returns the raw data of a section.
func (f *File) SectionData(sec *pe.Section) ([]byte, error) {
	return sec.Data()
}

// Export describes a single PE export entry — exposes both name (which
// may be empty for ordinal-only exports) and the absolute ordinal so
// downstream tooling (notably pe/dllproxy) can emit forwarders for
// targets like msvcrt that ship many ordinal-only entries.
type Export struct {
	// Name is the function's exported name. Empty for ordinal-only
	// exports — those appear in AddressOfFunctions but not in
	// AddressOfNames / AddressOfNameOrdinals.
	Name string

	// Ordinal is the absolute (Base-biased) ordinal — the integer the
	// export is referenced by from import descriptors. PE spec calls
	// this the "ordinal value" as opposed to the per-array index.
	Ordinal uint16

	// Forwarder, when non-empty, indicates the export is itself a
	// forwarder to another DLL. The value is the canonical
	// "module.export" or "module.#ordinal" string — the loader follows
	// it transparently. Real exports leave this empty.
	Forwarder string
}

// ExportEntries returns the full export table — one Export per
// function slot, in ordinal order. Mirrors what the Windows loader
// itself sees: every ordinal-with-an-RVA appears, named or not.
//
// Use this when downstream code needs ordinal information (proxy DLL
// emission, export-table inspection, forwarder following). Use
// [File.Exports] for a simpler "give me the exported names" answer.
func (f *File) ExportEntries() ([]Export, error) {
	var exportDirRVA, exportDirSize uint32
	switch oh := f.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
			exportDirSize = oh.DataDirectory[0].Size
		}
	}
	if exportDirRVA == 0 {
		return nil, nil
	}
	offset := rvaToOffset(f.PE, exportDirRVA)
	if offset == 0 || int(offset+40) > len(f.Raw) {
		return nil, fmt.Errorf("invalid export directory offset")
	}

	base := binary.LittleEndian.Uint32(f.Raw[offset+16:])
	numFunctions := binary.LittleEndian.Uint32(f.Raw[offset+20:])
	numNames := binary.LittleEndian.Uint32(f.Raw[offset+24:])
	addrFunctions := binary.LittleEndian.Uint32(f.Raw[offset+28:])
	addrNames := binary.LittleEndian.Uint32(f.Raw[offset+32:])
	addrOrdinals := binary.LittleEndian.Uint32(f.Raw[offset+36:])

	functionsOff := rvaToOffset(f.PE, addrFunctions)
	namesOff := rvaToOffset(f.PE, addrNames)
	ordinalsOff := rvaToOffset(f.PE, addrOrdinals)
	if functionsOff == 0 || namesOff == 0 || ordinalsOff == 0 {
		return nil, fmt.Errorf("export sub-table RVA resolves outside known sections")
	}

	// Slot index → name (sparse: not every function slot has a name).
	nameByIndex := make(map[uint32]string, numNames)
	for i := uint32(0); i < numNames; i++ {
		nameRVA := binary.LittleEndian.Uint32(f.Raw[namesOff+i*4:])
		idx := uint32(binary.LittleEndian.Uint16(f.Raw[ordinalsOff+i*2:]))
		nameByIndex[idx] = readZString(f.Raw, rvaToOffset(f.PE, nameRVA))
	}

	out := make([]Export, 0, numFunctions)
	for i := uint32(0); i < numFunctions; i++ {
		funcRVA := binary.LittleEndian.Uint32(f.Raw[functionsOff+i*4:])
		if funcRVA == 0 {
			// Empty slot — ordinal not actually exported.
			continue
		}
		e := Export{
			Name:    nameByIndex[i],
			Ordinal: uint16(base + i),
		}
		// Forwarder detection: per PE spec, the function RVA is a
		// forwarder iff it falls inside the export-directory range.
		if funcRVA >= exportDirRVA && funcRVA < exportDirRVA+exportDirSize {
			fwdOff := rvaToOffset(f.PE, funcRVA)
			if fwdOff != 0 {
				e.Forwarder = readZString(f.Raw, fwdOff)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// readZString reads a NUL-terminated ASCII string starting at off in
// the given byte slice. Returns "" if off is out of bounds.
func readZString(buf []byte, off uint32) string {
	if off == 0 || int(off) >= len(buf) {
		return ""
	}
	end := off
	for end < uint32(len(buf)) && buf[end] != 0 {
		end++
	}
	return string(buf[off:end])
}

// Exports returns the names of all exported functions.
func (f *File) Exports() ([]string, error) {
	// Parse export directory
	var exportDirRVA uint32
	switch oh := f.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
		}
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 0 {
			exportDirRVA = oh.DataDirectory[0].VirtualAddress
		}
	}

	if exportDirRVA == 0 {
		return nil, nil // no exports
	}

	offset := rvaToOffset(f.PE, exportDirRVA)
	if offset == 0 || int(offset+40) > len(f.Raw) {
		return nil, fmt.Errorf("invalid export directory offset")
	}

	numNames := binary.LittleEndian.Uint32(f.Raw[offset+24:])
	addrNames := binary.LittleEndian.Uint32(f.Raw[offset+32:])
	namesOff := rvaToOffset(f.PE, addrNames)
	if namesOff == 0 {
		return nil, fmt.Errorf("export names RVA resolves outside known sections")
	}

	var names []string
	for i := uint32(0); i < numNames; i++ {
		nameRVA := binary.LittleEndian.Uint32(f.Raw[namesOff+i*4:])
		nameOff := rvaToOffset(f.PE, nameRVA)
		if nameOff == 0 {
			continue
		}
		end := nameOff
		for end < uint32(len(f.Raw)) && f.Raw[end] != 0 {
			end++
		}
		names = append(names, string(f.Raw[nameOff:end]))
	}
	return names, nil
}

// Imports returns imported DLL names.
func (f *File) Imports() ([]string, error) {
	libs, err := f.PE.ImportedLibraries()
	if err != nil {
		return nil, err
	}
	return libs, nil
}

// Write saves the (potentially modified) PE to disk.
func (f *File) Write(path string) error {
	return os.WriteFile(path, f.Raw, 0644)
}

// WriteBytes returns the raw PE bytes.
func (f *File) WriteBytes() []byte {
	return f.Raw
}

// rvaToOffset converts an RVA to a file offset.
func rvaToOffset(f *pe.File, rva uint32) uint32 {
	for _, sec := range f.Sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
			return sec.Offset + (rva - sec.VirtualAddress)
		}
	}
	return 0
}
