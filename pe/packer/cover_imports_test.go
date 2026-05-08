package packer_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"os"
	"path/filepath"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// minimalPE32WithImports builds a synthetic PE32+ that has one
// existing import entry so tests can validate the merge behaviour.
// The import descriptor points at a fabricated ILT/IAT region inside
// the .rdata section; the exact values don't need to be valid —
// debug/pe parses the descriptor table without resolving DLL names.
func minimalPE32WithImports(numImports int) []byte {
	// Strategy: build a minimalPE32Plus, then manually inject a small
	// .rdata section containing a descriptor array. The synthesized
	// entries use nonzero OriginalFirstThunk / FirstThunk so the
	// terminator-scan loop in readExistingDescriptors stops correctly.
	// We keep the section count at 2 (.text + .rdata) to leave plenty
	// of section-header slack for the fake-imports section.

	const (
		hdrSpace     = 0x400
		sectionAlign = 0x1000
		fileAlign    = 0x200
		textRVA      = 0x1000
		entryRVA     = 0x1010
		imageBase    = 0x140000000
		optHdrSize   = 0xF0

		rdataRVA = 0x2000
		rdataRaw = 0x600 // file offset for .rdata (after .text body at 0x400, 0x200 raw)
	)

	// Fixed .text body: 0x200 bytes of NOPs.
	textRawSize := uint32(0x200)

	// Fixed .rdata body: descriptor array + ILT/IAT stubs.
	// Each existing entry needs a nonzero OFT and FT to not look like
	// a terminator. We point them at plausible-looking RVAs inside .rdata
	// itself (it won't be resolved; debug/pe only needs non-zero values
	// to walk past them when this is checked in the test).
	const (
		importDescSize = 20
		iltEntSize     = 8
	)
	rdataBodySize := numImports*importDescSize + (numImports+1)*importDescSize /* terminator */
	if rdataBodySize < 0x200 {
		rdataBodySize = 0x200
	}
	rdataRawSize := uint32(alignUp(rdataBodySize, fileAlign))

	totalFile := rdataRaw + int(rdataRawSize)
	buf := make([]byte, totalFile)

	// DOS header.
	copy(buf[0:2], "MZ")
	peOff := uint32(0x80)
	put32(buf[0x3C:], peOff)

	// PE signature.
	copy(buf[peOff:peOff+4], "PE\x00\x00")
	coff := peOff + 4
	put16(buf[coff+0x00:], 0x8664) // AMD64
	put16(buf[coff+0x02:], 2)      // two sections
	put16(buf[coff+0x10:], optHdrSize)
	put16(buf[coff+0x12:], 0x0022) // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

	opt := coff + 20
	put16(buf[opt+0x00:], 0x20B) // PE32+
	buf[opt+0x02] = 14
	put32(buf[opt+0x04:], 0x200) // SizeOfCode
	put32(buf[opt+0x10:], entryRVA)
	put32(buf[opt+0x14:], textRVA)
	put64(buf[opt+0x18:], uint64(imageBase))
	put32(buf[opt+0x20:], sectionAlign)
	put32(buf[opt+0x24:], fileAlign)
	put16(buf[opt+0x28:], 6) // MajorOSVersion
	put16(buf[opt+0x30:], 6) // MajorSubsystemVersion
	put32(buf[opt+0x38:], rdataRVA+sectionAlign) // SizeOfImage
	put32(buf[opt+0x3C:], hdrSpace)               // SizeOfHeaders
	put16(buf[opt+0x44:], 3)                       // CUI subsystem
	put32(buf[opt+0x68:], 0)                       // LoaderFlags
	put32(buf[opt+0x6C:], 16)                      // NumberOfRvaAndSizes

	// DataDirectory[1] = Import Directory → .rdata start.
	importDirOffset := opt + 0x70 + 1*8
	put32(buf[importDirOffset:], rdataRVA) // RVA
	put32(buf[importDirOffset+4:], uint32(numImports+1)*importDescSize) // Size

	// Section headers.
	sec0 := opt + optHdrSize
	// .text
	copy(buf[sec0:sec0+8], ".text\x00\x00\x00")
	put32(buf[sec0+0x08:], 0x200) // VirtualSize
	put32(buf[sec0+0x0C:], textRVA)
	put32(buf[sec0+0x10:], textRawSize)
	put32(buf[sec0+0x14:], hdrSpace)  // PointerToRawData
	put32(buf[sec0+0x24:], 0x60000020)

	// .rdata
	sec1 := sec0 + 40
	copy(buf[sec1:sec1+8], ".rdata\x00\x00")
	put32(buf[sec1+0x08:], uint32(rdataBodySize)) // VirtualSize
	put32(buf[sec1+0x0C:], rdataRVA)
	put32(buf[sec1+0x10:], rdataRawSize)
	put32(buf[sec1+0x14:], rdataRaw) // PointerToRawData
	put32(buf[sec1+0x24:], 0x40000040)

	// Write fake existing import descriptors in .rdata body.
	// Each has a nonzero OFT/FT pointing somewhere in the .rdata RVA
	// range so the terminator scanner doesn't stop early.
	for i := 0; i < numImports; i++ {
		base := rdataRaw + i*importDescSize
		// OFT: point at some offset inside .rdata (won't be dereferenced)
		put32(buf[base+0x00:], rdataRVA+uint32(numImports*importDescSize+i*iltEntSize))
		// TimeDateStamp: 0
		// ForwarderChain: 0xFFFFFFFF
		put32(buf[base+0x08:], 0xFFFFFFFF)
		// Name: point inside .rdata (fake)
		put32(buf[base+0x0C:], rdataRVA+0x100+uint32(i*8))
		// FT
		put32(buf[base+0x10:], rdataRVA+uint32(numImports*importDescSize+i*iltEntSize))
	}
	// Zero terminator is already zero from make.

	// Fill .text with NOPs.
	for i := hdrSpace; i < hdrSpace+int(textRawSize); i++ {
		buf[i] = 0x90
	}

	return buf
}

// TestAddFakeImportsPE_RejectsEmptyFakes verifies that passing an
// empty fakes slice returns ErrCoverInvalidOptions immediately.
func TestAddFakeImportsPE_RejectsEmptyFakes(t *testing.T) {
	input := minimalPE32Plus(0x100)
	_, err := packerpkg.AddFakeImportsPE(input, nil)
	if !errors.Is(err, packerpkg.ErrCoverInvalidOptions) {
		t.Errorf("got %v, want ErrCoverInvalidOptions", err)
	}
}

// TestAddFakeImportsPE_RejectsNonPE verifies that non-PE input is
// rejected with ErrCoverInvalidOptions.
func TestAddFakeImportsPE_RejectsNonPE(t *testing.T) {
	_, err := packerpkg.AddFakeImportsPE([]byte("not a PE"), packerpkg.DefaultFakeImports)
	if !errors.Is(err, packerpkg.ErrCoverInvalidOptions) {
		t.Errorf("got %v, want ErrCoverInvalidOptions", err)
	}
}

// TestAddFakeImportsPE_DebugPEParses builds a synthetic PE with no
// prior imports, adds DefaultFakeImports (4 DLLs), and confirms
// debug/pe round-trips the output including ImportedSymbols. The
// synthetic PE starts with an empty DataDirectory[1] so the existing-
// descriptor path returns nil and only the four fake entries are
// written.
func TestAddFakeImportsPE_DebugPEParses(t *testing.T) {
	// minimalPE32Plus has no DataDirectory entries (NumberOfRvaAndSizes
	// is 16 but all entries are zero), so DataDirectory[1] RVA = 0 and
	// readExistingDescriptors returns nil — only fakes are written.
	input := minimalPE32Plus(0x200)

	out, err := packerpkg.AddFakeImportsPE(input, packerpkg.DefaultFakeImports)
	if err != nil {
		t.Fatalf("AddFakeImportsPE: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()

	syms, err := f.ImportedSymbols()
	if err != nil {
		t.Fatalf("ImportedSymbols: %v", err)
	}

	// Count distinct DLLs seen in the output via section name check.
	// The original fake descriptor used synthetic values so debug/pe may
	// not list it; count the fake ones we can verify: 4 new DLLs.
	dllsSeen := map[string]bool{}
	for _, sym := range syms {
		// Format: "Sym:DLL" — extract DLL name after last ':'.
		for j := len(sym) - 1; j >= 0; j-- {
			if sym[j] == ':' {
				dllsSeen[sym[j+1:]] = true
				break
			}
		}
	}

	for _, want := range []string{"kernel32.dll", "user32.dll", "shell32.dll", "ole32.dll"} {
		if !dllsSeen[want] {
			t.Errorf("expected DLL %q not found in ImportedSymbols (got %v)", want, dllsSeen)
		}
	}
}

// TestAddFakeImportsPE_PreservesExistingImports confirms the invariant
// that matters for runtime correctness: existing entries' FirstThunk
// RVAs are byte-identical between input and output. The loader patches
// the IAT via FirstThunk, so that value must not change.
//
// OriginalFirstThunk is intentionally relocated into the new section
// so that the import directory is fully self-contained (debug/pe and
// the loader both require all descriptor data to be reachable from
// the section DataDirectory[1] points at). The test confirms this
// relocation happened (OFT points into the new section).
func TestAddFakeImportsPE_PreservesExistingImports(t *testing.T) {
	const numExisting = 2
	input := minimalPE32WithImports(numExisting)

	out, err := packerpkg.AddFakeImportsPE(input, packerpkg.DefaultFakeImports)
	if err != nil {
		t.Fatalf("AddFakeImportsPE: %v", err)
	}

	outF, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer outF.Close()

	var idata2 *pe.Section
	for _, s := range outF.Sections {
		if s.Name == ".idata2" {
			idata2 = s
			break
		}
	}
	if idata2 == nil {
		t.Fatal(".idata2 section missing from output")
	}

	outBody, err := idata2.Data()
	if err != nil {
		t.Fatalf(".idata2 Data(): %v", err)
	}

	// Original descriptors lived in .rdata at PointerToRawData = 0x600.
	const (
		rdataRaw     = 0x600
		importDescSz = 20
		rdataRVA     = 0x2000
	)

	for i := 0; i < numExisting; i++ {
		origBase := rdataRaw + i*importDescSz
		outBase := i * importDescSz

		// FirstThunk (offset 0x10) MUST be identical — binary code uses it.
		origFT := readU32LE(input[origBase+0x10:])
		outFT := readU32LE(outBody[outBase+0x10:])
		if origFT != outFT {
			t.Errorf("descriptor %d: FirstThunk changed: want %#x got %#x", i, origFT, outFT)
		}

		// OriginalFirstThunk MUST be relocated into .idata2
		// (VA range [idata2.VirtualAddress, idata2.VirtualAddress+VirtualSize)).
		outOFT := readU32LE(outBody[outBase:])
		idata2VA := idata2.VirtualAddress
		idata2End := idata2VA + idata2.VirtualSize
		if outOFT < idata2VA || outOFT >= idata2End {
			t.Errorf("descriptor %d: OriginalFirstThunk %#x not in .idata2 [%#x, %#x)",
				i, outOFT, idata2VA, idata2End)
		}
	}
}

// TestAddFakeImportsPE_RealFixture packs testdata/winhello.exe and
// then chains AddFakeImportsPE. Confirms debug/pe round-trips and
// that ImportedSymbols includes each function from DefaultFakeImports.
func TestAddFakeImportsPE_RealFixture(t *testing.T) {
	fixturePath := filepath.Join("testdata", "winhello.exe")
	input, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Skipf("Windows fixture missing (%v); run scripts/build-winhello.sh", err)
	}

	packed, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}

	out, err := packerpkg.AddFakeImportsPE(packed, packerpkg.DefaultFakeImports)
	if err != nil {
		t.Fatalf("AddFakeImportsPE: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()

	syms, err := f.ImportedSymbols()
	if err != nil {
		t.Fatalf("ImportedSymbols: %v", err)
	}

	// Verify every function from DefaultFakeImports appears in the symbol list.
	symSet := make(map[string]bool, len(syms))
	for _, s := range syms {
		symSet[s] = true
	}

	for _, fi := range packerpkg.DefaultFakeImports {
		for _, fn := range fi.Functions {
			key := fn + ":" + fi.DLL
			if !symSet[key] {
				t.Errorf("expected symbol %q not found; have %v", key, syms)
			}
		}
	}
}

// readU32LE reads a little-endian uint32 from b without requiring
// encoding/binary in tests — keeps the test helper self-contained.
func readU32LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
