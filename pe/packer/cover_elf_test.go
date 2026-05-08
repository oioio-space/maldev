package packer_test

import (
	"bytes"
	"debug/elf"
	"errors"
	"os"
	"path/filepath"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestAddCoverELF_RejectsEmptyOptions covers the JunkSections=0 path.
func TestAddCoverELF_RejectsEmptyOptions(t *testing.T) {
	input := []byte{0x7F, 'E', 'L', 'F', 2, 1, 1, 0}
	input = append(input, make([]byte, 64)...)
	_, err := packerpkg.AddCoverELF(input, packerpkg.CoverOptions{})
	if !errors.Is(err, packerpkg.ErrCoverInvalidOptions) {
		t.Errorf("got %v, want ErrCoverInvalidOptions", err)
	}
}

// TestAddCoverELF_RejectsNonELF covers the magic-byte gate.
func TestAddCoverELF_RejectsNonELF(t *testing.T) {
	_, err := packerpkg.AddCoverELF([]byte("not an elf"),
		packerpkg.CoverOptions{JunkSections: []packerpkg.JunkSection{{Size: 0x100}}})
	if !errors.Is(err, packerpkg.ErrCoverInvalidOptions) {
		t.Errorf("got %v, want ErrCoverInvalidOptions on non-ELF input", err)
	}
}

// TestAddCoverELF_RelocatesPHTOnGoStaticPIE_Smoke confirms that the
// cover layer now succeeds for Go static-PIE inputs (first PT_LOAD at
// file offset 0 → no PHT slack). v0.62.0 lifted the previous
// ErrCoverSectionTableFull limitation by relocating the PHT to
// file-end. The full assertion (PT_LOAD count, e_phoff change,
// debug/elf parse) lives in cover_elf_reloc_test.go; this test only
// confirms the function no longer returns an error.
func TestAddCoverELF_RelocatesPHTOnGoStaticPIE_Smoke(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("runtime", "testdata", "hello_static_pie"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	_, err = packerpkg.AddCoverELF(input, packerpkg.CoverOptions{
		JunkSections: []packerpkg.JunkSection{{Size: 0x100, Fill: packerpkg.JunkFillZero}},
	})
	if err != nil {
		t.Errorf("AddCoverELF on Go static-PIE returned error: %v (want nil — PHT relocation should succeed)", err)
	}
}

// TestAddCoverELF_HappyPath_DebugELFParses uses a synthetic ELF
// with slack between the PHT and the first PT_LOAD's file offset.
// Verifies debug/elf parses the output and PT_LOAD count grew by
// JunkSections count.
func TestAddCoverELF_HappyPath_DebugELFParses(t *testing.T) {
	input := minimalELF64WithSlack(0x500)
	pre, err := elf.NewFile(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("debug/elf rejected synthetic input: %v", err)
	}
	preLoadCount := 0
	for _, p := range pre.Progs {
		if p.Type == elf.PT_LOAD {
			preLoadCount++
		}
	}
	pre.Close()

	out, err := packerpkg.AddCoverELF(input, packerpkg.CoverOptions{
		JunkSections: []packerpkg.JunkSection{
			{Size: 0x200, Fill: packerpkg.JunkFillRandom},
			{Size: 0x100, Fill: packerpkg.JunkFillPattern},
		},
	})
	if err != nil {
		t.Fatalf("AddCoverELF: %v", err)
	}
	post, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected covered output: %v", err)
	}
	defer post.Close()

	postLoadCount := 0
	for _, p := range post.Progs {
		if p.Type == elf.PT_LOAD {
			postLoadCount++
		}
	}
	if postLoadCount != preLoadCount+2 {
		t.Errorf("PT_LOAD count = %d, want %d", postLoadCount, preLoadCount+2)
	}
}

// minimalELF64WithSlack constructs a synthetic ELF64 with one
// PT_LOAD R+E and 8 phdr slots of slack between the PHT and the
// first PT_LOAD's file offset. Used to exercise the cover-layer
// happy path without needing a fixture that has PHT slack.
func minimalELF64WithSlack(textSize uint64) []byte {
	const (
		page    = 0x1000
		ehdrSz  = 64
		phdrSz  = 56
		entryVA = 0x401000
	)
	textOff := uint64(page)
	totalSize := textOff + transform.AlignUpU64(textSize, page)
	buf := make([]byte, totalSize)

	// Ehdr.
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = 2 // EI_CLASS = 64
	buf[5] = 1 // EI_DATA = LE
	buf[6] = 1 // EI_VERSION
	put16(buf[0x10:], 3)                             // e_type = ET_DYN
	put16(buf[0x12:], 0x3E)                          // e_machine = AMD64
	put32(buf[0x14:], 1)                             // e_version
	put64(buf[0x18:], entryVA)                       // e_entry
	put64(buf[0x20:], ehdrSz)                        // e_phoff (immediately after Ehdr)
	put64(buf[0x28:], 0)                             // e_shoff (no SHT)
	put32(buf[0x30:], 0)                             // e_flags
	put16(buf[0x34:], ehdrSz)                        // e_ehsize
	put16(buf[0x36:], phdrSz)                        // e_phentsize
	put16(buf[0x38:], 1)                             // e_phnum (start with 1)
	put16(buf[0x3A:], 0)                             // e_shentsize
	put16(buf[0x3C:], 0)                             // e_shnum
	put16(buf[0x3E:], 0)                             // e_shstrndx

	// One PT_LOAD R+E at textOff.
	ph := uint64(ehdrSz)
	put32(buf[ph+0x00:], 1)             // p_type = PT_LOAD
	put32(buf[ph+0x04:], 5)             // p_flags = R+X
	put64(buf[ph+0x08:], textOff)       // p_offset
	put64(buf[ph+0x10:], entryVA)       // p_vaddr
	put64(buf[ph+0x18:], entryVA)       // p_paddr
	put64(buf[ph+0x20:], textSize)      // p_filesz
	put64(buf[ph+0x28:], textSize)      // p_memsz
	put64(buf[ph+0x30:], page)          // p_align

	// Sentinel byte at e_entry's file offset (textOff + 0) just
	// to signal a non-zero text body; not exercised by the tests.
	buf[textOff] = 0x90
	return buf
}

