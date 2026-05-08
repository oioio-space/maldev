package transform_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// buildMinimalELF emits a minimal ELF64 with one PT_LOAD R+E segment
// and a section-header table containing a null entry, a .text section,
// and a .shstrtab section. The section-header table is required because
// PlanELF uses debug/elf to locate .text precisely — Go static-PIE
// binaries embed the ELF header inside the first executable PT_LOAD
// (file offset 0), so encrypting the whole segment would corrupt the
// header.
func buildMinimalELF(t *testing.T, opts minimalELFOpts) []byte {
	t.Helper()
	const (
		ehdrSize = 64
		phdrSize = 56
		shdrSize = 64 // Elf64_Shdr
		pageSize = 0x1000
	)

	if opts.TextSize == 0 {
		opts.TextSize = 0x100
	}

	// Layout:
	//   [0x00, 0x40)  Ehdr
	//   [0x40, 0x78)  Phdr[0]  (PT_LOAD R+E)
	//   [0x78, 0x88)  slack (fits one more phdr slot for InjectStubELF)
	//   [0x88, 0xF0)  shstrtab (section name string table)
	//   [pageSize, pageSize+TextSize)  .text bytes
	//   [pageSize+TextSize, …)  shdrs (3 entries)
	//
	// The slack between phdr table end (0x78) and .text start (pageSize)
	// gives InjectStubELF room to append one new phdr entry.

	shstrtab := []byte("\x00.text\x00.shstrtab\x00")
	shstrtabOff := uint64(ehdrSize + phdrSize*2) // 0x78 — after 2 phdr slots
	textOff := uint64(pageSize)
	textVAddr := textOff // identity-mapped for simplicity
	if opts.TextEntry == 0 {
		opts.TextEntry = textVAddr + 0x10
	}

	// Section headers follow immediately after the text section.
	shOff := textOff + uint64(opts.TextSize)
	// Align to 8 bytes.
	shOff = (shOff + 7) &^ 7

	totalSize := shOff + uint64(shdrSize*3)
	out := make([]byte, totalSize)

	// --- Ehdr ---
	out[0] = 0x7F; out[1] = 'E'; out[2] = 'L'; out[3] = 'F'
	out[4] = 2 // ELFCLASS64
	out[5] = 1 // ELFDATA2LSB
	out[6] = 1 // EV_CURRENT
	binary.LittleEndian.PutUint16(out[0x10:], 3)      // ET_DYN
	binary.LittleEndian.PutUint16(out[0x12:], 62)     // EM_X86_64
	binary.LittleEndian.PutUint32(out[0x14:], 1)      // e_version
	binary.LittleEndian.PutUint64(out[0x18:], opts.TextEntry) // e_entry
	binary.LittleEndian.PutUint64(out[0x20:], ehdrSize)       // e_phoff
	binary.LittleEndian.PutUint64(out[0x28:], shOff)          // e_shoff
	binary.LittleEndian.PutUint16(out[0x34:], ehdrSize)       // e_ehsize
	binary.LittleEndian.PutUint16(out[0x36:], phdrSize)       // e_phentsize
	binary.LittleEndian.PutUint16(out[0x38:], 1)              // e_phnum
	binary.LittleEndian.PutUint16(out[0x3A:], shdrSize)       // e_shentsize
	binary.LittleEndian.PutUint16(out[0x3C:], 3)              // e_shnum
	binary.LittleEndian.PutUint16(out[0x3E:], 2)              // e_shstrndx

	// --- Phdr[0]: PT_LOAD R+E covering the full text segment ---
	p0 := uint64(ehdrSize)
	binary.LittleEndian.PutUint32(out[p0:], 1)                        // PT_LOAD
	binary.LittleEndian.PutUint32(out[p0+4:], 5)                      // PF_R|PF_X
	binary.LittleEndian.PutUint64(out[p0+8:], textOff)                // p_offset
	binary.LittleEndian.PutUint64(out[p0+16:], textVAddr)             // p_vaddr
	binary.LittleEndian.PutUint64(out[p0+24:], textVAddr)             // p_paddr
	binary.LittleEndian.PutUint64(out[p0+32:], uint64(opts.TextSize)) // p_filesz
	binary.LittleEndian.PutUint64(out[p0+40:], uint64(opts.TextSize)) // p_memsz
	binary.LittleEndian.PutUint64(out[p0+48:], pageSize)              // p_align

	// --- shstrtab bytes at shstrtabOff ---
	copy(out[shstrtabOff:], shstrtab)

	// --- Section headers at shOff ---
	// SHdr[0]: null — all-zero, already set by make.

	// SHdr[1]: .text — name offset 1 in shstrtab ("\x00.text\x00…")
	s1 := shOff + shdrSize
	binary.LittleEndian.PutUint32(out[s1:], 1)                                       // sh_name
	binary.LittleEndian.PutUint32(out[s1+4:], uint32(elf.SHT_PROGBITS))              // sh_type
	binary.LittleEndian.PutUint64(out[s1+8:], uint64(elf.SHF_ALLOC|elf.SHF_EXECINSTR)) // sh_flags
	binary.LittleEndian.PutUint64(out[s1+16:], textVAddr)                             // sh_addr
	binary.LittleEndian.PutUint64(out[s1+24:], textOff)                               // sh_offset
	binary.LittleEndian.PutUint64(out[s1+32:], uint64(opts.TextSize))                 // sh_size
	binary.LittleEndian.PutUint64(out[s1+48:], 1)                                     // sh_addralign

	// SHdr[2]: .shstrtab — name offset 7 ("\x00.text\x00.shstrtab\x00")
	s2 := shOff + shdrSize*2
	binary.LittleEndian.PutUint32(out[s2:], 7)                           // sh_name
	binary.LittleEndian.PutUint32(out[s2+4:], uint32(elf.SHT_STRTAB))   // sh_type
	// sh_addr = 0: .shstrtab is not loaded into memory
	binary.LittleEndian.PutUint64(out[s2+24:], shstrtabOff)              // sh_offset
	binary.LittleEndian.PutUint64(out[s2+32:], uint64(len(shstrtab)))    // sh_size
	binary.LittleEndian.PutUint64(out[s2+48:], 1)                        // sh_addralign

	return out
}

type minimalELFOpts struct {
	TextSize  uint32
	TextEntry uint64
}

// fixtureBytes reads pe/packer/runtime/testdata/hello_static_pie and
// skips the test if the file is absent (non-Linux CI without the fixture).
func fixtureBytes(t *testing.T) []byte {
	t.Helper()
	// Navigate from pe/packer/transform/ up to pe/packer/, then into runtime/testdata.
	path := filepath.Join("..", "runtime", "testdata", "hello_static_pie")
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Skipf("fixture path resolution failed: %v", err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Skipf("hello_static_pie fixture not found (%v) — skipping", err)
	}
	return data
}

// ---- existing tests (updated for SHT-aware buildMinimalELF) ----------------

func TestPlanELF_HappyPath(t *testing.T) {
	// TextEntry must be inside the .text section (vaddr = pageSize = 0x1000,
	// size = 0x500), so pick 0x1010.
	elfBytes := buildMinimalELF(t, minimalELFOpts{TextSize: 0x500, TextEntry: 0x1010})
	plan, err := transform.PlanELF(elfBytes, 4096)
	if err != nil {
		t.Fatalf("PlanELF: %v", err)
	}
	if plan.Format != transform.FormatELF {
		t.Errorf("Format = %v, want ELF", plan.Format)
	}
	if plan.TextSize != 0x500 {
		t.Errorf("TextSize = %#x, want 0x500", plan.TextSize)
	}
	if plan.OEPRVA != 0x1010 {
		t.Errorf("OEPRVA = %#x, want 0x1010", plan.OEPRVA)
	}
	if plan.StubRVA == 0 {
		t.Error("StubRVA = 0")
	}
}

func TestPlanELF_RejectsOEPOutsideText(t *testing.T) {
	elfBytes := buildMinimalELF(t, minimalELFOpts{
		TextSize:  0x100,
		TextEntry: 0x9000, // well past .text end (0x1000 + 0x100)
	})
	_, err := transform.PlanELF(elfBytes, 4096)
	if !errors.Is(err, transform.ErrOEPOutsideText) {
		t.Errorf("got %v, want ErrOEPOutsideText", err)
	}
}

func TestInjectStubELF_DebugELFParses(t *testing.T) {
	// Exercise both the synthetic fixture and the real Go binary (when present).
	t.Run("synthetic", func(t *testing.T) {
		input := buildMinimalELF(t, minimalELFOpts{TextSize: 0x500, TextEntry: 0x1010})
		injectAndVerifyELF(t, input)
	})
	t.Run("real_fixture", func(t *testing.T) {
		input := fixtureBytes(t)
		injectAndVerifyELF(t, input)
	})
}

// injectAndVerifyELF is the shared body: plan → inject → debug/elf parse.
func injectAndVerifyELF(t *testing.T, input []byte) {
	t.Helper()
	plan, err := transform.PlanELF(input, 4096)
	if err != nil {
		t.Fatalf("PlanELF: %v", err)
	}
	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := []byte{0x90, 0x90, 0xC3}

	out, err := transform.InjectStubELF(input, encryptedText, stubBytes, plan)
	if err != nil {
		t.Fatalf("InjectStubELF: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected: %v", err)
	}
	defer f.Close()

	if f.FileHeader.Type != elf.ET_DYN {
		t.Errorf("Type = %v, want ET_DYN", f.FileHeader.Type)
	}
	if uint32(f.FileHeader.Entry) != plan.StubRVA {
		t.Errorf("Entry = %#x, want StubRVA %#x", f.FileHeader.Entry, plan.StubRVA)
	}
	loadCount := 0
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			loadCount++
		}
	}
	if loadCount < 2 {
		t.Errorf("PT_LOAD count = %d, want ≥ 2 (text + new stub)", loadCount)
	}
}

func TestInjectStubELF_RejectsStubTooLarge(t *testing.T) {
	input := buildMinimalELF(t, minimalELFOpts{})
	plan, err := transform.PlanELF(input, 16)
	if err != nil {
		t.Fatalf("PlanELF: %v", err)
	}
	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := bytes.Repeat([]byte{0x90}, 100)
	_, err = transform.InjectStubELF(input, encryptedText, stubBytes, plan)
	if !errors.Is(err, transform.ErrStubTooLarge) {
		t.Errorf("got %v, want ErrStubTooLarge", err)
	}
}

// TestInjectStubELF_HonoursTextMemSize verifies that setting Plan.TextMemSize >
// Plan.TextSize causes InjectStubELF to widen p_memsz in the executable PT_LOAD
// while leaving p_filesz at the original (compressed) size. The kernel
// zero-fills [p_filesz, p_memsz) at load time — the workspace the in-place LZ4
// inflate decoder expands into.
func TestInjectStubELF_HonoursTextMemSize(t *testing.T) {
	const textSize = 0x200
	input := buildMinimalELF(t, minimalELFOpts{TextSize: textSize, TextEntry: 0x1010})
	plan, err := transform.PlanELF(input, 4096)
	if err != nil {
		t.Fatalf("PlanELF: %v", err)
	}

	plan.TextMemSize = plan.TextSize * 2 // double the virtual window

	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := []byte{0x90, 0xC3}

	out, err := transform.InjectStubELF(input, encryptedText, stubBytes, plan)
	if err != nil {
		t.Fatalf("InjectStubELF: %v", err)
	}

	// Parse with debug/elf to confirm the output is well-formed.
	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected output: %v", err)
	}
	defer f.Close()

	// Find the executable PT_LOAD and verify p_memsz was widened.
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if uint32(prog.Memsz) != plan.TextMemSize {
			t.Errorf("executable PT_LOAD p_memsz = %#x, want TextMemSize %#x",
				prog.Memsz, plan.TextMemSize)
		}
		// p_filesz must remain at the original size (on-disk compressed payload).
		if uint32(prog.Filesz) != plan.TextSize {
			t.Errorf("executable PT_LOAD p_filesz = %#x, want TextSize %#x",
				prog.Filesz, plan.TextSize)
		}
		return
	}
	t.Error("no executable PT_LOAD found in output")
}

// TestInjectStubELF_TextMemSizeIgnoredWhenSmall confirms that Plan.TextMemSize
// <= Plan.TextSize is a no-op: p_memsz in the output equals the original p_memsz.
func TestInjectStubELF_TextMemSizeIgnoredWhenSmall(t *testing.T) {
	const textSize = 0x200
	input := buildMinimalELF(t, minimalELFOpts{TextSize: textSize, TextEntry: 0x1010})

	for _, memSize := range []uint32{0, textSize} {
		plan, err := transform.PlanELF(input, 4096)
		if err != nil {
			t.Fatalf("PlanELF: %v", err)
		}
		plan.TextMemSize = memSize

		encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
		out, err := transform.InjectStubELF(input, encryptedText, []byte{0x90, 0xC3}, plan)
		if err != nil {
			t.Fatalf("TextMemSize=%d InjectStubELF: %v", memSize, err)
		}

		f, err := elf.NewFile(bytes.NewReader(out))
		if err != nil {
			t.Fatalf("debug/elf rejected: %v", err)
		}
		for _, prog := range f.Progs {
			if prog.Type == elf.PT_LOAD && prog.Flags&elf.PF_X != 0 {
				if uint32(prog.Memsz) != textSize {
					t.Errorf("TextMemSize=%d: p_memsz=%#x, want %#x",
						memSize, prog.Memsz, textSize)
				}
				break
			}
		}
		f.Close()
	}
}

// ---- new tests for the SHT-based .text lookup (Bug 1 fix) ------------------

// TestPlanELF_GoStaticPIEFixture confirms that PlanELF uses the .text
// SECTION rather than the enclosing PT_LOAD. Go static-PIE binaries place
// the ELF header in the first executable PT_LOAD (file offset 0); using
// the segment bounds directly would set TextFileOff=0 and destroy the header.
func TestPlanELF_GoStaticPIEFixture(t *testing.T) {
	input := fixtureBytes(t)
	plan, err := transform.PlanELF(input, 4096)
	if err != nil {
		t.Fatalf("PlanELF: %v", err)
	}

	// .text starts at file offset 0x1000 in the fixture — well past the
	// ELF header + phdr table. Any value of 0 here means we accidentally
	// used the PT_LOAD bounds.
	if plan.TextFileOff == 0 {
		t.Errorf("TextFileOff = 0: PlanELF is using PT_LOAD origin, not .text section")
	}

	// TextSize must be smaller than the total file — segment-wide encryption
	// would yield TextSize ≈ len(input).
	if plan.TextSize >= uint32(len(input)) {
		t.Errorf("TextSize %d ≥ len(input) %d: looks like PT_LOAD, not .text", plan.TextSize, len(input))
	}

	// TextRVA must match the .text section's virtual address in the fixture
	// (0x401000 as confirmed by readelf -S).
	const wantTextVAddr = 0x401000
	if plan.TextRVA != wantTextVAddr {
		t.Errorf("TextRVA = %#x, want %#x (.text section vaddr)", plan.TextRVA, wantTextVAddr)
	}
}

// TestInjectStubELF_PreservesELFHeader verifies that packing the real Go
// static-PIE fixture does not touch the ELF header or the phdr table.
// Because Go binaries put the ELF header inside the first executable
// PT_LOAD, a correct implementation must narrow encryption to .text only.
func TestInjectStubELF_PreservesELFHeader(t *testing.T) {
	const (
		ehdrSize = 64
		phdrSize = 56
	)
	input := fixtureBytes(t)
	plan, err := transform.PlanELF(input, 4096)
	if err != nil {
		t.Fatalf("PlanELF: %v", err)
	}

	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := []byte{0x90, 0x90, 0xC3}
	out, err := transform.InjectStubELF(input, encryptedText, stubBytes, plan)
	if err != nil {
		t.Fatalf("InjectStubELF: %v", err)
	}

	// ELF header [0, 64) must be byte-identical (except e_entry + e_phnum,
	// which InjectStubELF legally mutates).
	for i := 0; i < ehdrSize; i++ {
		if i >= 0x18 && i < 0x20 { // e_entry range — intentionally rewritten
			continue
		}
		if i >= 0x38 && i < 0x3A { // e_phnum range — intentionally bumped
			continue
		}
		if out[i] != input[i] {
			t.Errorf("ELF header byte [%d] = %#02x, want %#02x (from input)", i, out[i], input[i])
		}
	}

	// The phdr table must be preserved (InjectStubELF only appends, never rewrites
	// existing entries other than adding PF_W to the text segment flags).
	phoff := binary.LittleEndian.Uint64(input[0x20 : 0x20+8])
	phnum := binary.LittleEndian.Uint16(input[0x38 : 0x38+2])
	phTableEnd := phoff + uint64(phnum)*phdrSize
	if int(phTableEnd) > len(input) {
		t.Fatal("phdr table extends past input — fixture malformed")
	}
	// Check every existing phdr slot for preservation (flags byte excluded for
	// the text PT_LOAD since PF_W is ORed in).
	for i := uint16(0); i < phnum; i++ {
		off := phoff + uint64(i)*phdrSize
		for j := uint64(0); j < phdrSize; j++ {
			// Skip the flags field of the text PT_LOAD (PF_W is intentionally added).
			if j >= 4 && j < 8 {
				continue
			}
			if out[off+j] != input[off+j] {
				t.Errorf("phdr[%d] byte [%d] = %#02x, want %#02x", i, j, out[off+j], input[off+j])
			}
		}
	}
}

// TestInjectStubELF_DebugELFParsesRealFixture is a standalone guard that
// debug/elf.NewFile accepts the packed output of the real Go static-PIE fixture.
// Kept separate from TestInjectStubELF_DebugELFParses so failures are easy
// to triage by fixture vs synthetic.
func TestInjectStubELF_DebugELFParsesRealFixture(t *testing.T) {
	input := fixtureBytes(t)
	plan, err := transform.PlanELF(input, 4096)
	if err != nil {
		t.Fatalf("PlanELF: %v", err)
	}
	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := []byte{0x90, 0x90, 0xC3}

	out, err := transform.InjectStubELF(input, encryptedText, stubBytes, plan)
	if err != nil {
		t.Fatalf("InjectStubELF: %v", err)
	}

	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf.NewFile rejected packed output: %v", err)
	}
	defer f.Close()

	if uint32(f.FileHeader.Entry) != plan.StubRVA {
		t.Errorf("e_entry = %#x, want StubRVA %#x", f.FileHeader.Entry, plan.StubRVA)
	}
}
