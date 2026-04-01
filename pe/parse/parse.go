// Package parse provides PE file parsing and modification utilities.
//
// This wraps the standard library debug/pe package with additional
// helpers for maldev operations like section enumeration, export
// resolution, and header manipulation.
//
// Platform: Cross-platform (parses Windows PE files on any OS).
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
