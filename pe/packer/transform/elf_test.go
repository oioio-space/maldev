package transform_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// buildMinimalELF emits a minimal Elf64 with one PT_LOAD R+E
// segment (the "text" equivalent). Optional textOEP places the
// entry point inside the segment.
func buildMinimalELF(t *testing.T, opts minimalELFOpts) []byte {
	t.Helper()
	const ehdrSize = 64
	const phdrSize = 56
	const pageSize = 0x1000

	if opts.TextSize == 0 {
		opts.TextSize = 0x100
	}
	textOff := uint64(ehdrSize + phdrSize) // right after phdr
	textOff = (textOff + pageSize - 1) &^ (pageSize - 1)
	textVAddr := textOff
	if opts.TextEntry == 0 {
		opts.TextEntry = textVAddr + 0x10
	}

	totalSize := textOff + uint64(opts.TextSize)
	out := make([]byte, totalSize)

	// e_ident
	out[0] = 0x7F
	out[1] = 'E'
	out[2] = 'L'
	out[3] = 'F'
	out[4] = 2 // EI_CLASS = ELFCLASS64
	out[5] = 1 // EI_DATA = ELFDATA2LSB
	out[6] = 1 // EI_VERSION
	// Ehdr fields
	binary.LittleEndian.PutUint16(out[0x10:0x12], 3)  // ET_DYN
	binary.LittleEndian.PutUint16(out[0x12:0x14], 62) // EM_X86_64
	binary.LittleEndian.PutUint32(out[0x14:0x18], 1)
	binary.LittleEndian.PutUint64(out[0x18:0x20], opts.TextEntry)
	binary.LittleEndian.PutUint64(out[0x20:0x28], ehdrSize) // e_phoff
	binary.LittleEndian.PutUint16(out[0x34:0x36], ehdrSize) // e_ehsize
	binary.LittleEndian.PutUint16(out[0x36:0x38], phdrSize) // e_phentsize
	binary.LittleEndian.PutUint16(out[0x38:0x3A], 1)        // e_phnum

	// Phdr (PT_LOAD R+E)
	pOff := uint64(ehdrSize)
	binary.LittleEndian.PutUint32(out[pOff:pOff+4], 1)                              // PT_LOAD
	binary.LittleEndian.PutUint32(out[pOff+4:pOff+8], 5)                            // PF_R | PF_X
	binary.LittleEndian.PutUint64(out[pOff+8:pOff+16], textOff)                     // p_offset
	binary.LittleEndian.PutUint64(out[pOff+16:pOff+24], textVAddr)                  // p_vaddr
	binary.LittleEndian.PutUint64(out[pOff+24:pOff+32], textVAddr)                  // p_paddr
	binary.LittleEndian.PutUint64(out[pOff+32:pOff+40], uint64(opts.TextSize))      // p_filesz
	binary.LittleEndian.PutUint64(out[pOff+40:pOff+48], uint64(opts.TextSize))      // p_memsz
	binary.LittleEndian.PutUint64(out[pOff+48:pOff+56], pageSize)
	return out
}

type minimalELFOpts struct {
	TextSize  uint32
	TextEntry uint64
}

func TestPlanELF_HappyPath(t *testing.T) {
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
		TextEntry: 0x9000, // way past
	})
	_, err := transform.PlanELF(elfBytes, 4096)
	if !errors.Is(err, transform.ErrOEPOutsideText) {
		t.Errorf("got %v, want ErrOEPOutsideText", err)
	}
}

func TestInjectStubELF_DebugELFParses(t *testing.T) {
	input := buildMinimalELF(t, minimalELFOpts{TextSize: 0x500, TextEntry: 0x1010})
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
	if loadCount != 2 {
		t.Errorf("PT_LOAD count = %d, want 2 (text + new stub)", loadCount)
	}
}

func TestInjectStubELF_RejectsStubTooLarge(t *testing.T) {
	input := buildMinimalELF(t, minimalELFOpts{})
	plan, _ := transform.PlanELF(input, 16)
	encryptedText := bytes.Repeat([]byte{0xAA}, int(plan.TextSize))
	stubBytes := bytes.Repeat([]byte{0x90}, 100)
	_, err := transform.InjectStubELF(input, encryptedText, stubBytes, plan)
	if !errors.Is(err, transform.ErrStubTooLarge) {
		t.Errorf("got %v, want ErrStubTooLarge", err)
	}
}
