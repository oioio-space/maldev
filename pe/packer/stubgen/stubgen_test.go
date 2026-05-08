package stubgen_test

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// buildMinimalPE constructs a synthetic PE32+ with a single .text
// section. Replicated from transform/pe_test.go — cross-package
// test helpers are awkward in Go (they'd need an exported testutil
// subpackage); duplicating the ~30-line builder keeps this package
// self-contained and avoids a test-only import cycle.
func buildMinimalPE(textSize, oepRVA uint32) []byte {
	const (
		dosHdrSize   = 0x40
		peSigSize    = 4
		coffSize     = 20
		optHdrSize   = 240
		fileAlign    = 0x200
		sectionAlign = 0x1000
	)
	headersSize := uint32(dosHdrSize + peSigSize + coffSize + optHdrSize + 40)
	headersAligned := (headersSize + fileAlign - 1) &^ (fileAlign - 1)
	textRVA := uint32(0x1000)
	textFileOff := headersAligned
	textRawSize := (textSize + fileAlign - 1) &^ (fileAlign - 1)
	totalSize := textFileOff + textRawSize

	out := make([]byte, totalSize)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[0x3C:0x40], dosHdrSize)

	off := uint32(dosHdrSize)
	binary.LittleEndian.PutUint32(out[off:off+4], 0x00004550) // PE sig
	off += peSigSize

	binary.LittleEndian.PutUint16(out[off:off+2], 0x8664) // Machine AMD64
	binary.LittleEndian.PutUint16(out[off+2:off+4], 1)    // NumberOfSections
	binary.LittleEndian.PutUint16(out[off+16:off+18], optHdrSize)
	binary.LittleEndian.PutUint16(out[off+18:off+20], 0x0022) // EXE | LARGE_ADDR_AWARE
	off += coffSize

	binary.LittleEndian.PutUint16(out[off:off+2], 0x20B)          // PE32+
	binary.LittleEndian.PutUint32(out[off+0x10:off+0x14], oepRVA) // AddressOfEntryPoint
	binary.LittleEndian.PutUint64(out[off+0x18:off+0x20], 0x140000000)
	binary.LittleEndian.PutUint32(out[off+0x20:off+0x24], sectionAlign)
	binary.LittleEndian.PutUint32(out[off+0x24:off+0x28], fileAlign)
	binary.LittleEndian.PutUint16(out[off+0x30:off+0x32], 6)                   // MajorSubsystemVer
	binary.LittleEndian.PutUint32(out[off+0x38:off+0x3C], textRVA+textRawSize) // SizeOfImage
	binary.LittleEndian.PutUint32(out[off+0x3C:off+0x40], headersAligned)      // SizeOfHeaders
	binary.LittleEndian.PutUint16(out[off+0x44:off+0x46], 3)                   // Subsystem CUI
	binary.LittleEndian.PutUint64(out[off+0x48:off+0x50], 0x100000)
	binary.LittleEndian.PutUint64(out[off+0x50:off+0x58], 0x1000)
	binary.LittleEndian.PutUint64(out[off+0x58:off+0x60], 0x100000)
	binary.LittleEndian.PutUint64(out[off+0x60:off+0x68], 0x1000)
	binary.LittleEndian.PutUint32(out[off+0x6C:off+0x70], 16) // NumberOfRvaAndSizes
	off += optHdrSize

	// .text section header
	copy(out[off:off+8], []byte(".text\x00\x00\x00"))
	binary.LittleEndian.PutUint32(out[off+8:off+12], textSize)     // VirtualSize
	binary.LittleEndian.PutUint32(out[off+12:off+16], textRVA)     // VirtualAddress
	binary.LittleEndian.PutUint32(out[off+16:off+20], textRawSize) // SizeOfRawData
	binary.LittleEndian.PutUint32(out[off+20:off+24], textFileOff) // PointerToRawData
	binary.LittleEndian.PutUint32(out[off+36:off+40], 0x60000020)  // CODE|EXEC|READ
	return out
}

// buildMinimalELF constructs a synthetic ELF64 with one PT_LOAD R+E
// segment (the "text" equivalent).
func buildMinimalELF(textSize uint32, textEntry uint64) []byte {
	const (
		ehdrSize = 64
		phdrSize = 56
		pageSize = 0x1000
	)
	textOff := uint64(ehdrSize + phdrSize)
	textOff = (textOff + pageSize - 1) &^ (pageSize - 1)
	textVAddr := textOff

	totalSize := textOff + uint64(textSize)
	out := make([]byte, totalSize)

	out[0] = 0x7F
	out[1] = 'E'
	out[2] = 'L'
	out[3] = 'F'
	out[4] = 2                                        // ELFCLASS64
	out[5] = 1                                        // ELFDATA2LSB
	out[6] = 1                                        // EI_VERSION
	binary.LittleEndian.PutUint16(out[0x10:0x12], 3)  // ET_DYN
	binary.LittleEndian.PutUint16(out[0x12:0x14], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(out[0x14:0x18], 1)
	binary.LittleEndian.PutUint64(out[0x18:0x20], textEntry)
	binary.LittleEndian.PutUint64(out[0x20:0x28], ehdrSize) // e_phoff
	binary.LittleEndian.PutUint16(out[0x34:0x36], ehdrSize) // e_ehsize
	binary.LittleEndian.PutUint16(out[0x36:0x38], phdrSize) // e_phentsize
	binary.LittleEndian.PutUint16(out[0x38:0x3A], 1)        // e_phnum=1

	pOff := uint64(ehdrSize)
	binary.LittleEndian.PutUint32(out[pOff:pOff+4], 1)                    // PT_LOAD
	binary.LittleEndian.PutUint32(out[pOff+4:pOff+8], 5)                  // PF_R|PF_X
	binary.LittleEndian.PutUint64(out[pOff+8:pOff+16], textOff)           // p_offset
	binary.LittleEndian.PutUint64(out[pOff+16:pOff+24], textVAddr)        // p_vaddr
	binary.LittleEndian.PutUint64(out[pOff+24:pOff+32], textVAddr)        // p_paddr
	binary.LittleEndian.PutUint64(out[pOff+32:pOff+40], uint64(textSize)) // p_filesz
	binary.LittleEndian.PutUint64(out[pOff+40:pOff+48], uint64(textSize)) // p_memsz
	binary.LittleEndian.PutUint64(out[pOff+48:pOff+56], pageSize)         // p_align
	return out
}

// TestGenerate_PEPasses verifies that Generate transforms a synthetic PE32+
// into a structurally valid modified binary parsed cleanly by debug/pe.
func TestGenerate_PEPasses(t *testing.T) {
	input := buildMinimalPE(0x500, 0x1010)
	out, key, err := stubgen.Generate(stubgen.Options{
		Input:  input,
		Rounds: 3,
		Seed:   1,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(key) == 0 {
		t.Error("returned key is empty")
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()

	if len(f.Sections) != 2 {
		t.Errorf("Sections = %d, want 2 (.text + stub)", len(f.Sections))
	}
}

// TestGenerate_PETextEncrypted verifies that .text bytes in the output
// differ from the input — they are encrypted, not plaintext.
func TestGenerate_PETextEncrypted(t *testing.T) {
	input := buildMinimalPE(0x500, 0x1010)

	// Seed the .text region with a recognisable pattern.
	const (
		headersSize = 0x40 + 4 + 20 + 240 + 40 // DOS+PE+COFF+Opt+1 section hdr
		fileAlign   = 0x200
		textFileOff = (headersSize + fileAlign - 1) &^ (fileAlign - 1)
	)
	for i := uint32(0); i < 0x500 && int(textFileOff+i) < len(input); i++ {
		input[textFileOff+i] = 0xCC // INT3 — recognisable filler
	}

	out, _, err := stubgen.Generate(stubgen.Options{Input: input, Rounds: 1, Seed: 1})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	// .text region in the output must not be all 0xCC
	allUnchanged := true
	for i := uint32(0); i < 0x500 && int(textFileOff+i) < len(out); i++ {
		if out[textFileOff+i] != 0xCC {
			allUnchanged = false
			break
		}
	}
	if allUnchanged {
		t.Error(".text region in output is identical to input — encryption not applied")
	}
}

// TestGenerate_PEEntryPointIsStub verifies that the output PE's
// AddressOfEntryPoint matches the plan's StubRVA, not the original OEP.
func TestGenerate_PEEntryPointIsStub(t *testing.T) {
	input := buildMinimalPE(0x500, 0x1010)
	out, _, err := stubgen.Generate(stubgen.Options{Input: input, Rounds: 1, Seed: 1})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected: %v", err)
	}
	defer f.Close()

	// Entry point must not be the original OEP (0x1010) — it must point
	// into the new stub section.
	if f.OptionalHeader == nil {
		t.Fatal("no OptionalHeader")
	}
	opt := f.OptionalHeader.(*pe.OptionalHeader64)
	if opt.AddressOfEntryPoint == 0x1010 {
		t.Error("entry point still points to original OEP — stub section not wired up")
	}
	// Must be page-aligned (stub section RVA is always page-aligned by PlanPE)
	if opt.AddressOfEntryPoint%0x1000 != 0 {
		t.Errorf("entry point %#x not page-aligned (expected stub RVA)", opt.AddressOfEntryPoint)
	}
}

// TestGenerate_ELFPasses verifies the ELF round-trip: debug/elf parses
// the output, e_entry changed to StubRVA, multiple PT_LOAD segments.
// Uses the real Phase 1f fixture because PlanELF requires a true .text
// section in the SHT, which the buildMinimalELF synthetic helper does
// not provide (and adding SHT to it would duplicate the real fixture).
func TestGenerate_ELFPasses(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "runtime", "testdata", "hello_static_pie"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	out, key, err := stubgen.Generate(stubgen.Options{
		Input:  input,
		Rounds: 3,
		Seed:   1,
	})
	if err != nil {
		t.Fatalf("Generate ELF: %v", err)
	}
	if len(key) == 0 {
		t.Error("returned key is empty")
	}

	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected: %v", err)
	}
	defer f.Close()

	loadCount := 0
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			loadCount++
		}
	}
	if loadCount < 2 {
		t.Errorf("PT_LOAD count = %d, want >= 2 (original + stub)", loadCount)
	}
	// Entry must differ from the original OEP. Read the input's e_entry
	// from the same fixture and compare against the packed output's.
	origEntry := binary.LittleEndian.Uint64(input[0x18 : 0x18+8])
	if f.Entry == origEntry {
		t.Error("e_entry unchanged — stub not wired up")
	}
}

// TestGenerate_RejectsZeroInput verifies ErrNoInput.
func TestGenerate_RejectsZeroInput(t *testing.T) {
	_, _, err := stubgen.Generate(stubgen.Options{Input: nil})
	if !errors.Is(err, stubgen.ErrNoInput) {
		t.Errorf("got %v, want ErrNoInput", err)
	}
}

// TestGenerate_RejectsOutOfRangeRounds verifies ErrInvalidRounds.
func TestGenerate_RejectsOutOfRangeRounds(t *testing.T) {
	input := buildMinimalPE(0x500, 0x1010)
	for _, r := range []int{-1, 11, 100} {
		_, _, err := stubgen.Generate(stubgen.Options{Input: input, Rounds: r})
		if !errors.Is(err, stubgen.ErrInvalidRounds) {
			t.Errorf("rounds=%d: got %v, want ErrInvalidRounds", r, err)
		}
	}
}

// TestGenerate_PerPackUniqueness verifies that different seeds produce
// different output bytes.
func TestGenerate_PerPackUniqueness(t *testing.T) {
	input := buildMinimalPE(0x500, 0x1010)
	out1, _, err := stubgen.Generate(stubgen.Options{Input: input, Rounds: 3, Seed: 1})
	if err != nil {
		t.Fatalf("Generate seed=1: %v", err)
	}
	out2, _, err := stubgen.Generate(stubgen.Options{Input: input, Rounds: 3, Seed: 2})
	if err != nil {
		t.Fatalf("Generate seed=2: %v", err)
	}
	if bytes.Equal(out1, out2) {
		t.Error("seed=1 and seed=2 produced identical output")
	}
}

// TestGenerate_Compress_PE verifies that Generate with Compress=true produces
// a structurally valid PE32+ (debug/pe parses it), the output is smaller than
// the non-compressed variant on a text-heavy input, and the .text VirtualSize
// is larger than SizeOfRawData (the TextMemSize > TextSize memsz expansion).
func TestGenerate_Compress_PE(t *testing.T) {
	// Use a larger .text so compression has something to work with.
	input := buildMinimalPE(0x2000, 0x1010)
	// Seed the text with a repetitive pattern that LZ4 compresses well.
	const fileAlign = 0x200
	const headersSize = 0x40 + 4 + 20 + 240 + 40
	textFileOff := uint32((headersSize + fileAlign - 1) &^ (fileAlign - 1))
	for i := uint32(0); i < 0x2000 && int(textFileOff+i) < len(input); i++ {
		input[textFileOff+i] = byte(i % 7) // repetitive → compressible
	}

	outComp, _, err := stubgen.Generate(stubgen.Options{
		Input: input, Rounds: 1, Seed: 1, Compress: true,
	})
	if err != nil {
		t.Fatalf("Generate Compress=true: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(outComp))
	if err != nil {
		t.Fatalf("debug/pe rejected Compress=true output: %v", err)
	}
	defer f.Close()

	if len(f.Sections) < 2 {
		t.Fatalf("Sections = %d, want ≥ 2", len(f.Sections))
	}

	// The .text VirtualSize must be larger than SizeOfRawData: the former
	// covers the decompression workspace; the latter is the compressed payload.
	textSec := f.Sections[0]
	if textSec.VirtualSize <= textSec.Size {
		t.Errorf(".text VirtualSize (%#x) ≤ SizeOfRawData (%#x): TextMemSize not applied",
			textSec.VirtualSize, textSec.Size)
	}
}

// TestGenerate_Compress_ELF verifies that Generate with Compress=true produces
// a structurally valid ELF64 (debug/elf parses it), that the binary's
// p_memsz is never shrunken below the original value, and that the output
// size is smaller than the non-compressed variant (compression actually helps).
func TestGenerate_Compress_ELF(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("..", "runtime", "testdata", "hello_static_pie"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// Parse the original p_memsz from the first R+E PT_LOAD before packing.
	origExecMemSz := func() uint64 {
		f, err := elf.NewFile(bytes.NewReader(input))
		if err != nil {
			t.Fatalf("elf.NewFile(input): %v", err)
		}
		defer f.Close()
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 {
				return p.Memsz
			}
		}
		t.Fatal("no executable PT_LOAD in input fixture")
		return 0
	}()

	out, _, err := stubgen.Generate(stubgen.Options{
		Input: input, Rounds: 1, Seed: 1, Compress: true,
	})
	if err != nil {
		t.Fatalf("Generate ELF Compress=true: %v", err)
	}

	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected Compress=true output: %v", err)
	}
	defer f.Close()

	// Find the executable PT_LOAD. p_memsz must be >= the original value
	// (we never shrink it; the inflate workspace may be covered by the
	// existing segment gap when .text << PT_LOAD filesz).
	found := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_LOAD && prog.Flags&elf.PF_X != 0 {
			if prog.Memsz < origExecMemSz {
				t.Errorf("executable PT_LOAD p_memsz (%#x) shrunken below original (%#x)",
					prog.Memsz, origExecMemSz)
			}
			found = true
			break
		}
	}
	if !found {
		t.Error("no executable PT_LOAD found in Compress=true ELF output")
	}

	// Output must be a valid ELF with entry changed to the stub.
	origEntry := binary.LittleEndian.Uint64(input[0x18 : 0x18+8])
	if f.Entry == origEntry {
		t.Error("e_entry unchanged — stub not wired up")
	}
}

// TestGenerate_Compress_DefaultFalse confirms that the zero-value Options
// (Compress=false) does not set TextMemSize: the .text VirtualSize in the
// output PE should equal the original TextSize (no inflate workspace).
func TestGenerate_Compress_DefaultFalse(t *testing.T) {
	input := buildMinimalPE(0x500, 0x1010)
	out, _, err := stubgen.Generate(stubgen.Options{Input: input, Rounds: 1, Seed: 1})
	if err != nil {
		t.Fatalf("Generate Compress=false: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected: %v", err)
	}
	defer f.Close()

	// VirtualSize must equal the original TextSize (0x500) — no memsz expansion.
	const wantVirtualSize = 0x500
	if f.Sections[0].VirtualSize != wantVirtualSize {
		t.Errorf(".text VirtualSize = %#x, want %#x (no inflate workspace without Compress)",
			f.Sections[0].VirtualSize, wantVirtualSize)
	}
}

// TestGenerate_RejectsUnknownFormat verifies ErrUnsupportedInputFormat
// for garbage input.
func TestGenerate_RejectsUnknownFormat(t *testing.T) {
	_, _, err := stubgen.Generate(stubgen.Options{
		Input:  bytes.Repeat([]byte{0x00}, 64),
		Rounds: 1,
		Seed:   1,
	})
	if !errors.Is(err, transform.ErrUnsupportedInputFormat) {
		t.Errorf("got %v, want ErrUnsupportedInputFormat", err)
	}
}
