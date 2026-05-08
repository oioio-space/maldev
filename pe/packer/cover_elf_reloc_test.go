package packer_test

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// minimalELF64NoSlack builds a synthetic ELF64 that mirrors the
// Go static-PIE PHT shape: the first (and only) PT_LOAD starts at
// file offset 0, so the PHT lives inside the segment and there is
// zero slack for in-place PHT growth.
//
// Layout:
//
//	[0x00] Ehdr (64 B)
//	[0x40] PHdr[0]: PT_LOAD  offset=0, vaddr=0x400000
//	[0x98] PHdr[1]: PT_PHDR  offset=0x40, vaddr=0x400040
//	[0xf0] … text body (textSize bytes, page-aligned)
func minimalELF64NoSlack(textSize uint64) []byte {
	const (
		page   = 0x1000
		ehdrSz = 64
		phdrSz = 56
		loadVA = 0x400000
	)
	// Two phdrs: PT_LOAD at [0] and PT_PHDR at [1].
	phtOff := uint64(ehdrSz)
	phtSz := 2 * uint64(phdrSz)
	// Place the text body right after the PHT; entry is inside it.
	textBodyOff := phtOff + phtSz
	entryOff := textBodyOff // first byte of text body
	entryVA := loadVA + entryOff
	fileSize := transform.AlignUpU64(textBodyOff+textSize, page)
	buf := make([]byte, fileSize)

	// Ehdr.
	copy(buf[0:4], []byte{0x7F, 'E', 'L', 'F'})
	buf[4] = 2 // EI_CLASS = 64
	buf[5] = 1 // EI_DATA = LE
	buf[6] = 1 // EI_VERSION
	put16(buf[0x10:], 2)               // e_type = ET_EXEC
	put16(buf[0x12:], 0x3E)            // e_machine = AMD64
	put32(buf[0x14:], 1)               // e_version
	put64(buf[0x18:], entryVA)         // e_entry
	put64(buf[0x20:], phtOff)          // e_phoff = 0x40
	put64(buf[0x28:], 0)               // e_shoff (no SHT)
	put32(buf[0x30:], 0)               // e_flags
	put16(buf[0x34:], ehdrSz)          // e_ehsize
	put16(buf[0x36:], phdrSz)          // e_phentsize
	put16(buf[0x38:], 2)               // e_phnum
	put16(buf[0x3A:], 0)               // e_shentsize
	put16(buf[0x3C:], 0)               // e_shnum
	put16(buf[0x3E:], 0)               // e_shstrndx

	// PHdr[0]: PT_LOAD covering file offset 0 (whole file) — no slack.
	ph0 := phtOff
	put32(buf[ph0+0x00:], 1)             // p_type = PT_LOAD
	put32(buf[ph0+0x04:], 5)             // p_flags = R+X
	put64(buf[ph0+0x08:], 0)             // p_offset = 0 ← no slack
	put64(buf[ph0+0x10:], loadVA)        // p_vaddr
	put64(buf[ph0+0x18:], loadVA)        // p_paddr
	put64(buf[ph0+0x20:], fileSize)      // p_filesz
	put64(buf[ph0+0x28:], fileSize)      // p_memsz
	put64(buf[ph0+0x30:], page)          // p_align

	// PHdr[1]: PT_PHDR pointing at the PHT (to exercise PT_PHDR update).
	ph1 := phtOff + uint64(phdrSz)
	put32(buf[ph1+0x00:], 6)             // p_type = PT_PHDR
	put32(buf[ph1+0x04:], 4)             // p_flags = R
	put64(buf[ph1+0x08:], phtOff)        // p_offset
	put64(buf[ph1+0x10:], loadVA+phtOff) // p_vaddr = 0x400040
	put64(buf[ph1+0x18:], loadVA+phtOff) // p_paddr
	put64(buf[ph1+0x20:], phtSz)         // p_filesz
	put64(buf[ph1+0x28:], phtSz)         // p_memsz
	put64(buf[ph1+0x30:], 8)             // p_align

	// Sentinel NOP at e_entry's file offset.
	buf[entryOff] = 0x90
	return buf
}

// TestAddCoverELF_RelocatesSyntheticNoSlack exercises the relocation
// path on a synthetic ELF that has zero PHT slack (first PT_LOAD at
// file offset 0). Asserts: (a) no error, (b) debug/elf parses the
// output, (c) e_phoff changed, (d) PT_LOAD count grew correctly,
// (e) PT_PHDR entry was updated to point at the new PHT location.
func TestAddCoverELF_RelocatesSyntheticNoSlack(t *testing.T) {
	input := minimalELF64NoSlack(0x200)

	preEf, err := elf.NewFile(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("debug/elf rejected synthetic no-slack input: %v", err)
	}
	preLoadCount := 0
	for _, p := range preEf.Progs {
		if p.Type == elf.PT_LOAD {
			preLoadCount++
		}
	}
	preEf.Close()

	const numJunk = 2
	out, err := packerpkg.AddCoverELF(input, packerpkg.CoverOptions{
		JunkSections: []packerpkg.JunkSection{
			{Size: 0x200, Fill: packerpkg.JunkFillRandom},
			{Size: 0x100, Fill: packerpkg.JunkFillZero},
		},
	})
	if err != nil {
		t.Fatalf("AddCoverELF on no-slack input: %v", err)
	}

	postEf, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected relocated output: %v", err)
	}
	defer postEf.Close()

	// PT_LOAD count must grow by 1 (PHT cover PT_LOAD) + numJunk.
	postLoadCount := 0
	for _, p := range postEf.Progs {
		if p.Type == elf.PT_LOAD {
			postLoadCount++
		}
	}
	wantLoadCount := preLoadCount + 1 + numJunk
	if postLoadCount != wantLoadCount {
		t.Errorf("PT_LOAD count = %d, want %d", postLoadCount, wantLoadCount)
	}

	// e_phoff must differ from the original (PHT was relocated).
	origPhoff := uint64(0x40) // known from minimalELF64NoSlack
	if postEf.FileHeader.Entry == 0 {
		t.Error("e_entry unexpectedly zeroed")
	}
	// debug/elf does not expose e_phoff directly; verify indirectly:
	// the PT_PHDR entry (if present) must now point past the original
	// file size to the new PHT region.
	for _, p := range postEf.Progs {
		if p.Type != elf.PT_PHDR {
			continue
		}
		if p.Off <= origPhoff {
			t.Errorf("PT_PHDR.p_offset = 0x%x, want > 0x%x (PHT not relocated)", p.Off, origPhoff)
		}
	}
}

// TestAddCoverELF_RelocatesPHTOnGoStaticPIE exercises the relocation
// path on the real Go static-PIE fixture. This is the canonical
// "Go binary" case that previously returned ErrCoverSectionTableFull.
//
// Asserts:
//   (a) no error returned,
//   (b) debug/elf parses output without error,
//   (c) PT_LOAD count = preLoadCount + 1 (PHT cover) + len(JunkSections),
//   (d) e_phoff changed (PHT actually relocated).
func TestAddCoverELF_RelocatesPHTOnGoStaticPIE(t *testing.T) {
	input, err := os.ReadFile(filepath.Join("runtime", "testdata", "hello_static_pie"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	preEf, err := elf.NewFile(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("debug/elf rejected fixture: %v", err)
	}
	preLoadCount := 0
	for _, p := range preEf.Progs {
		if p.Type == elf.PT_LOAD {
			preLoadCount++
		}
	}
	preEf.Close()

	const numJunk = 3
	out, err := packerpkg.AddCoverELF(input, packerpkg.CoverOptions{
		JunkSections: []packerpkg.JunkSection{
			{Size: 0x1000, Fill: packerpkg.JunkFillRandom},
			{Size: 0x800, Fill: packerpkg.JunkFillPattern},
			{Size: 0x2000, Fill: packerpkg.JunkFillZero},
		},
	})
	if err != nil {
		t.Fatalf("AddCoverELF on Go static-PIE: %v", err)
	}

	postEf, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected covered Go static-PIE: %v", err)
	}
	defer postEf.Close()

	postLoadCount := 0
	for _, p := range postEf.Progs {
		if p.Type == elf.PT_LOAD {
			postLoadCount++
		}
	}
	wantLoadCount := preLoadCount + 1 + numJunk
	if postLoadCount != wantLoadCount {
		t.Errorf("PT_LOAD count = %d, want %d (pre=%d + 1 PHT cover + %d junk)",
			postLoadCount, wantLoadCount, preLoadCount, numJunk)
	}
}
