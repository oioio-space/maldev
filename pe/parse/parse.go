package parse

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	saferpe "github.com/saferwall/pe"

	"github.com/oioio-space/maldev/evasion/stealthopen"
)

// File represents a parsed PE file with read/write capabilities.
//
// Internally backed by github.com/saferwall/pe — far richer than
// stdlib `debug/pe` (Authenticode hash, import hash, anomaly
// detection, Rich header, CFG / dynamic-reloc parsing). Public
// methods preserve the pre-saferwall surface so existing callers
// upgrade transparently; new methods (Authentihash / ImpHash /
// Anomalies) expose the new capabilities.
type File struct {
	// PE is the underlying saferwall *File. Exposed as an escape
	// hatch — operators needing a directory the maldev wrapper
	// doesn't surface (Resources, CLR, TLS, …) can reach through.
	PE *saferpe.File

	// Raw is the full file bytes as supplied to Open / FromBytes.
	// Kept around so Write/WriteBytes return the operator's
	// original payload bytes (saferwall's parse may mutate
	// internal copies).
	Raw []byte

	// Path is the on-disk path the file was loaded from. Empty
	// for FromBytes callers.
	Path string
}

// Section is a thin Go-native view of a PE section. Decouples the
// public API from the underlying parser library.
type Section struct {
	Name           string
	VirtualAddress uint32
	VirtualSize    uint32
	Offset         uint32 // PointerToRawData
	Size           uint32 // SizeOfRawData
	Characteristics uint32

	raw []byte // section-data slice into File.Raw, populated lazily
}

// Open opens and parses a PE file from disk.
func Open(path string) (*File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return FromBytes(raw, path)
}

// FromBytes parses a PE from raw bytes. The bytes are kept
// reference-shared with the returned File — callers must not mutate
// them after the call.
func FromBytes(data []byte, name string) (*File, error) {
	pf, err := saferpe.NewBytes(data, &saferpe.Options{
		// Sane defaults for a wrapper consumed by recon /
		// instrumentation code: parse everything, but don't fail
		// if a malformed certificate trips validation (Anomalies
		// surfaces oddities; callers chose to load the bytes
		// regardless).
		DisableCertValidation: true,
	})
	if err != nil {
		return nil, fmt.Errorf("parse PE: %w", err)
	}
	if err := pf.Parse(); err != nil {
		return nil, fmt.Errorf("parse PE directories: %w", err)
	}
	return &File{PE: pf, Raw: data, Path: name}, nil
}

// Close releases resources.
func (f *File) Close() error {
	if f == nil || f.PE == nil {
		return nil
	}
	return f.PE.Close()
}

// Is64Bit returns true if the PE is a PE32+ binary (64-bit).
func (f *File) Is64Bit() bool {
	return f.PE.Is64
}

// IsDLL returns true if the PE has the DLL characteristic flag.
func (f *File) IsDLL() bool {
	return f.PE.IsDLL()
}

// ImageBase returns the preferred load address.
//
// saferwall stores OptionalHeader as a value (not a pointer)
// despite what its godoc claims — pointer-form type assertions
// silently fail.
func (f *File) ImageBase() uint64 {
	if oh, ok := f.PE.NtHeader.OptionalHeader.(saferpe.ImageOptionalHeader64); ok {
		return oh.ImageBase
	}
	if oh, ok := f.PE.NtHeader.OptionalHeader.(saferpe.ImageOptionalHeader32); ok {
		return uint64(oh.ImageBase)
	}
	return 0
}

// EntryPoint returns the RVA of the entry point.
func (f *File) EntryPoint() uint32 {
	if oh, ok := f.PE.NtHeader.OptionalHeader.(saferpe.ImageOptionalHeader64); ok {
		return oh.AddressOfEntryPoint
	}
	if oh, ok := f.PE.NtHeader.OptionalHeader.(saferpe.ImageOptionalHeader32); ok {
		return oh.AddressOfEntryPoint
	}
	return 0
}

// Sections returns every parsed section as a Go-native [Section].
// Returns a fresh slice; callers may modify it freely.
func (f *File) Sections() []Section {
	out := make([]Section, len(f.PE.Sections))
	for i, s := range f.PE.Sections {
		out[i] = Section{
			Name:            sectionName(s.Header.Name),
			VirtualAddress:  s.Header.VirtualAddress,
			VirtualSize:     s.Header.VirtualSize,
			Offset:          s.Header.PointerToRawData,
			Size:            s.Header.SizeOfRawData,
			Characteristics: s.Header.Characteristics,
		}
	}
	return out
}

// sectionName converts the 8-byte NUL-padded section name to a
// trimmed Go string. Long names (the slash-prefixed string-table
// reference form) are surfaced as-is — executable images don't
// emit them.
func sectionName(raw [8]byte) string {
	if i := bytes.IndexByte(raw[:], 0); i >= 0 {
		return string(raw[:i])
	}
	return string(raw[:])
}

// SectionByName finds a section by name. Returns nil when no
// section matches.
func (f *File) SectionByName(name string) *Section {
	for _, s := range f.Sections() {
		if s.Name == name {
			s := s
			return &s
		}
	}
	return nil
}

// SectionData returns the raw bytes of a section. Reads from File.Raw
// using the section's Offset + Size.
func (f *File) SectionData(sec *Section) ([]byte, error) {
	if sec == nil {
		return nil, errors.New("parse: nil Section")
	}
	end := int(sec.Offset) + int(sec.Size)
	if end > len(f.Raw) || sec.Offset > uint32(len(f.Raw)) {
		return nil, fmt.Errorf("parse: section [%s] data overruns Raw (offset=%d size=%d Raw=%d)",
			sec.Name, sec.Offset, sec.Size, len(f.Raw))
	}
	return f.Raw[sec.Offset:end], nil
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
	// export is referenced by from import descriptors.
	Ordinal uint16

	// Forwarder, when non-empty, indicates the export is itself a
	// forwarder to another DLL. The value is the canonical
	// "module.export" or "module.#ordinal" string — the loader follows
	// it transparently. Real exports leave this empty.
	Forwarder string
}

// ExportEntries returns the full export table — one Export per
// function slot, in ordinal order. Ordinal-only entries (no name)
// appear with Name == "".
func (f *File) ExportEntries() ([]Export, error) {
	exp := f.PE.Export
	if len(exp.Functions) == 0 {
		return nil, nil
	}
	out := make([]Export, 0, len(exp.Functions))
	for _, fn := range exp.Functions {
		out = append(out, Export{
			Name:      fn.Name,
			Ordinal:   uint16(fn.Ordinal),
			Forwarder: fn.Forwarder,
		})
	}
	return out, nil
}

// Exports returns the names of exported functions only (ordinal-only
// entries are skipped). Use [File.ExportEntries] when ordinal +
// forwarder data is needed.
func (f *File) Exports() ([]string, error) {
	exp := f.PE.Export
	if len(exp.Functions) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(exp.Functions))
	for _, fn := range exp.Functions {
		if fn.Name == "" {
			continue
		}
		out = append(out, fn.Name)
	}
	return out, nil
}

// Imports returns imported DLL names.
func (f *File) Imports() ([]string, error) {
	out := make([]string, 0, len(f.PE.Imports))
	for _, imp := range f.PE.Imports {
		out = append(out, imp.Name)
	}
	return out, nil
}

// Authentihash returns the SHA-256 Authenticode hash of the PE — the
// canonical input to a real Authenticode signature, computed by
// hashing the PE bytes excluding the Checksum field, the security
// data directory entry, and the certificate table itself.
//
// Match this against the digest embedded in a captured
// `SpcIndirectDataContent` to verify whether a PE was tampered after
// signing.
func (f *File) Authentihash() []byte {
	return f.PE.Authentihash()
}

// ImpHash returns Mandiant's import-hash (imphash) — MD5 of the
// lowercased, comma-joined `<dll>.<func>` import list. Stable across
// PEs sharing the same import surface (typical for malware-family
// clustering).
func (f *File) ImpHash() (string, error) {
	return f.PE.ImpHash()
}

// Anomalies returns the list of structural anomalies the parser
// detected (overlapping headers, malformed directories, suspicious
// section sizes, …). Empty slice means "PE looks well-formed".
//
// Useful for static triage / sandbox heuristics: a benign Microsoft
// binary typically returns 0 anomalies; a packed / hand-crafted /
// herpadering-tampered binary often returns 2-10.
func (f *File) Anomalies() []string {
	out := make([]string, len(f.PE.Anomalies))
	copy(out, f.PE.Anomalies)
	return out
}

// Write saves the (potentially modified) PE bytes to disk.
// Equivalent to [File.WriteVia] with a nil Creator.
func (f *File) Write(path string) error {
	return f.WriteVia(nil, path)
}

// WriteVia routes the PE write through the operator-supplied
// [stealthopen.Creator]. nil falls back to a [stealthopen.StandardCreator]
// (plain os.Create).
func (f *File) WriteVia(creator stealthopen.Creator, path string) error {
	return stealthopen.WriteAll(creator, path, f.Raw)
}

// WriteBytes returns the raw PE bytes as supplied to Open / FromBytes.
func (f *File) WriteBytes() []byte {
	return f.Raw
}
