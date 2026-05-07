package packer_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// minimalPE32Plus builds a synthetic PE32+ with one .text section
// and 6 free section-header slots (10 NumberOfSections capacity in
// the table region between SizeOfHeaders and the first section).
// Returns a buffer the cover layer can extend without ErrCoverSectionTableFull.
func minimalPE32Plus(textSize uint32) []byte {
	const (
		hdrSpace      = 0x400 // file alignment
		sectionAlign  = 0x1000
		fileAlign     = 0x200
		textRVA       = 0x1000
		entryRVA      = 0x1010
		imageBase     = 0x140000000
		optHdrSize    = 0xF0
		coffSize      = 20
		peSig         = "PE\x00\x00"
		dosStubMzOnly = "MZ"
	)

	textBody := make([]byte, textSize)
	for i := range textBody {
		textBody[i] = 0x90
	}

	totalRaw := hdrSpace + alignUp(int(textSize), fileAlign)
	buf := make([]byte, totalRaw)

	// DOS header — only MZ + e_lfanew matter to debug/pe.
	copy(buf[0:2], "MZ")
	peOff := uint32(0x80)
	put32(buf[0x3C:], peOff)

	// PE signature.
	copy(buf[peOff:peOff+4], peSig)
	coff := peOff + 4
	put16(buf[coff+0x00:], 0x8664) // Machine = AMD64
	put16(buf[coff+0x02:], 1)      // NumberOfSections
	put32(buf[coff+0x04:], 0)      // TimeDateStamp
	put32(buf[coff+0x08:], 0)      // PointerToSymbolTable
	put32(buf[coff+0x0C:], 0)      // NumberOfSymbols
	put16(buf[coff+0x10:], optHdrSize)
	put16(buf[coff+0x12:], 0x2022) // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL? → use EXEC|LARGE
	// adjust: EXECUTABLE_IMAGE = 0x0002, LARGE_ADDRESS_AWARE = 0x0020 → 0x0022
	put16(buf[coff+0x12:], 0x0022)

	opt := coff + 20
	put16(buf[opt+0x00:], 0x20B) // Magic = PE32+
	buf[opt+0x02] = 14           // MajorLinkerVersion
	buf[opt+0x03] = 0            // MinorLinkerVersion
	put32(buf[opt+0x04:], textSize)
	put32(buf[opt+0x10:], entryRVA)
	put32(buf[opt+0x14:], textRVA)
	put64(buf[opt+0x18:], uint64(imageBase))
	put32(buf[opt+0x20:], sectionAlign)
	put32(buf[opt+0x24:], fileAlign)
	put16(buf[opt+0x28:], 6) // MajorOSVersion
	put16(buf[opt+0x2A:], 0)
	put16(buf[opt+0x2C:], 0) // MajorImageVersion
	put16(buf[opt+0x2E:], 0)
	put16(buf[opt+0x30:], 6) // MajorSubsystemVersion
	put16(buf[opt+0x32:], 0)
	put32(buf[opt+0x34:], 0)              // Win32VersionValue
	put32(buf[opt+0x38:], textRVA+sectionAlign)
	put32(buf[opt+0x3C:], hdrSpace)       // SizeOfHeaders
	put32(buf[opt+0x40:], 0)              // CheckSum
	put16(buf[opt+0x44:], 3)              // Subsystem = WINDOWS_CUI
	put16(buf[opt+0x46:], 0)              // DllCharacteristics
	put64(buf[opt+0x48:], 0x100000)       // SizeOfStackReserve
	put64(buf[opt+0x50:], 0x1000)         // SizeOfStackCommit
	put64(buf[opt+0x58:], 0x100000)       // SizeOfHeapReserve
	put64(buf[opt+0x60:], 0x1000)         // SizeOfHeapCommit
	put32(buf[opt+0x68:], 0)              // LoaderFlags
	put32(buf[opt+0x6C:], 16)             // NumberOfRvaAndSizes

	// Section header for .text.
	sec := opt + optHdrSize
	copy(buf[sec:sec+8], ".text\x00\x00\x00")
	put32(buf[sec+0x08:], textSize)
	put32(buf[sec+0x0C:], textRVA)
	put32(buf[sec+0x10:], uint32(alignUp(int(textSize), fileAlign)))
	put32(buf[sec+0x14:], hdrSpace) // PointerToRawData
	put32(buf[sec+0x24:], 0x60000020)

	// Copy text body into raw region.
	copy(buf[hdrSpace:], textBody)
	return buf
}

func alignUp(v, a int) int        { return (v + a - 1) &^ (a - 1) }
func put16(b []byte, v uint16)    { b[0] = byte(v); b[1] = byte(v >> 8) }
func put32(b []byte, v uint32)    { b[0] = byte(v); b[1] = byte(v >> 8); b[2] = byte(v >> 16); b[3] = byte(v >> 24) }
func put64(b []byte, v uint64)    { for i := 0; i < 8; i++ { b[i] = byte(v >> (i * 8)) } }

func TestAddCoverPE_RejectsEmptyOptions(t *testing.T) {
	input := minimalPE32Plus(0x100)
	_, err := packerpkg.AddCoverPE(input, packerpkg.CoverOptions{})
	if !errors.Is(err, packerpkg.ErrCoverInvalidOptions) {
		t.Errorf("got %v, want ErrCoverInvalidOptions", err)
	}
}

func TestAddCoverPE_RejectsNonPE(t *testing.T) {
	_, err := packerpkg.AddCoverPE([]byte("not a PE"),
		packerpkg.CoverOptions{JunkSections: []packerpkg.JunkSection{{Size: 0x100}}})
	if !errors.Is(err, packerpkg.ErrCoverInvalidOptions) {
		t.Errorf("got %v, want ErrCoverInvalidOptions on non-PE input", err)
	}
}

func TestAddCoverPE_HappyPath_DebugPEParses(t *testing.T) {
	input := minimalPE32Plus(0x200)
	out, err := packerpkg.AddCoverPE(input, packerpkg.CoverOptions{
		JunkSections: []packerpkg.JunkSection{
			{Name: ".rsrc", Size: 0x800, Fill: packerpkg.JunkFillRandom},
			{Name: ".rdata2", Size: 0x400, Fill: packerpkg.JunkFillPattern},
		},
	})
	if err != nil {
		t.Fatalf("AddCoverPE: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()

	if got := len(f.Sections); got != 3 {
		t.Errorf("section count = %d, want 3 (.text + 2 cover)", got)
	}
	names := make([]string, 0, 3)
	for _, s := range f.Sections {
		names = append(names, s.Name)
	}
	for _, want := range []string{".rsrc", ".rdata2"} {
		var found bool
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing cover section %q (got %v)", want, names)
		}
	}
}

func TestAddCoverPE_FillsAllStrategies(t *testing.T) {
	input := minimalPE32Plus(0x100)
	for _, fill := range []packerpkg.JunkFill{
		packerpkg.JunkFillRandom,
		packerpkg.JunkFillZero,
		packerpkg.JunkFillPattern,
	} {
		out, err := packerpkg.AddCoverPE(input, packerpkg.CoverOptions{
			JunkSections: []packerpkg.JunkSection{{Name: ".rsrc", Size: 0x200, Fill: fill}},
		})
		if err != nil {
			t.Errorf("fill=%d: %v", fill, err)
			continue
		}
		if _, err := pe.NewFile(bytes.NewReader(out)); err != nil {
			t.Errorf("fill=%d: debug/pe rejected output: %v", fill, err)
		}
	}
}

func TestAddCoverPE_PreservesOriginalSectionBody(t *testing.T) {
	// The cover layer must not touch the existing .text raw bytes
	// (the headers WILL change — NumberOfSections, SizeOfImage,
	// new section table entries — but the body region must be
	// byte-identical).
	input := minimalPE32Plus(0x100)
	out, err := packerpkg.AddCoverPE(input, packerpkg.CoverOptions{
		JunkSections: []packerpkg.JunkSection{{Size: 0x200, Fill: packerpkg.JunkFillRandom}},
	})
	if err != nil {
		t.Fatalf("AddCoverPE: %v", err)
	}
	// .text raw region: offset 0x400 (PointerToRawData) for 0x100 bytes (Size).
	if !bytes.Equal(out[0x400:0x500], input[0x400:0x500]) {
		t.Error("cover layer modified .text body bytes")
	}
}
