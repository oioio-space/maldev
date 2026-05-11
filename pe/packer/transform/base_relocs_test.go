package transform_test

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// peWithRelocs returns a synthetic PE buffer carrying ONE
// base-relocation block with two DIR64 entries + one ABSOLUTE
// padding entry. Just enough to exercise WalkBaseRelocs.
func peWithRelocs(t *testing.T) []byte {
	t.Helper()
	const (
		peOff         = 0x40
		coffOff       = peOff + 4
		sizeOfOptHdr  = 0xF0
		optOff        = coffOff + transform.PECOFFHdrSize
		secTableOff   = optOff + sizeOfOptHdr
		numSections   = 1
		sizeOfHeaders = 0x400
		sectionAlign  = 0x1000
		bufSize       = 0x2000
		// Section 0: VA 0x1000, raw at 0x400, size 0x100
		sec0VA      = 0x1000
		sec0RawOff  = 0x400
		sec0RawSize = 0x100
		// Reloc directory: lives inside section 0, at section-relative
		// offset 0x10 (so RVA 0x1010, file 0x410).
		relocDirRVA = 0x1010
		// Block: page 0x1000, blockSize = 8 (header) + 6 entries*2 = 20.
		// Entries: 1 ABSOLUTE (padding) + 2 DIR64 + 3 ABSOLUTE pad.
	)
	out := make([]byte, bufSize)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:], peOff)
	binary.LittleEndian.PutUint32(out[peOff:], 0x00004550)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFNumSectionsOffset:], numSections)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFSizeOfOptHdrOffset:], sizeOfOptHdr)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSectionAlignOffset:], sectionAlign)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptFileAlignOffset:], 0x200)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfImageOffset:], 0x2000)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfHeadersOffset:], sizeOfHeaders)

	// DataDirectory[5] (BaseRelocationTable) — RVA + Size.
	relocDirOff := optOff + transform.OptDataDirsStart + 5*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(out[relocDirOff:], relocDirRVA)
	binary.LittleEndian.PutUint32(out[relocDirOff+4:], 20) // block hdr (8) + 6 entries (12)

	// Section 0 header
	hdrOff := secTableOff
	copy(out[hdrOff:], ".text")
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualSizeOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualAddressOffset:], sec0VA)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecSizeOfRawDataOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecPointerToRawDataOffset:], sec0RawOff)

	// Reloc block at file 0x410 (RVA 0x1010 → file 0x400 + 0x10).
	const blockFileOff = sec0RawOff + (relocDirRVA - sec0VA)
	binary.LittleEndian.PutUint32(out[blockFileOff:], 0x1000)  // page RVA
	binary.LittleEndian.PutUint32(out[blockFileOff+4:], 20)    // block size
	// 6 entries (12 bytes). Entry layout: top 4 bits = type, bottom 12 = offset.
	entries := []uint16{
		uint16(transform.RelTypeAbsolute) << 12, // padding
		uint16(transform.RelTypeDir64)<<12 | 0x020,
		uint16(transform.RelTypeDir64)<<12 | 0x040,
		uint16(transform.RelTypeAbsolute) << 12, // pad to 8-byte align
		uint16(transform.RelTypeAbsolute) << 12,
		uint16(transform.RelTypeAbsolute) << 12,
	}
	for i, e := range entries {
		binary.LittleEndian.PutUint16(out[blockFileOff+8+uint32(i*2):], e)
	}
	return out
}

func TestWalkBaseRelocs_VisitsEveryEntry(t *testing.T) {
	pe := peWithRelocs(t)
	var entries []transform.BaseRelocEntry
	err := transform.WalkBaseRelocs(pe, func(e transform.BaseRelocEntry) error {
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkBaseRelocs: %v", err)
	}
	if got := len(entries); got != 6 {
		t.Errorf("visited %d entries, want 6", got)
	}
}

func TestWalkBaseRelocs_DecodesRVAAndType(t *testing.T) {
	pe := peWithRelocs(t)
	var dir64s []transform.BaseRelocEntry
	err := transform.WalkBaseRelocs(pe, func(e transform.BaseRelocEntry) error {
		if e.Type == transform.RelTypeDir64 {
			dir64s = append(dir64s, e)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkBaseRelocs: %v", err)
	}
	if len(dir64s) != 2 {
		t.Fatalf("got %d DIR64 entries, want 2", len(dir64s))
	}
	if dir64s[0].RVA != 0x1020 {
		t.Errorf("entries[0].RVA = 0x%x, want 0x1020 (page 0x1000 + offset 0x020)", dir64s[0].RVA)
	}
	if dir64s[1].RVA != 0x1040 {
		t.Errorf("entries[1].RVA = 0x%x, want 0x1040", dir64s[1].RVA)
	}
}

func TestWalkBaseRelocs_NoDirectoryReturnsNil(t *testing.T) {
	pe := peWithRelocs(t)
	// Zero out the BaseRelocationTable directory.
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	dirOff := optOff + transform.OptDataDirsStart + 5*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(pe[dirOff:], 0)
	binary.LittleEndian.PutUint32(pe[dirOff+4:], 0)

	called := false
	err := transform.WalkBaseRelocs(pe, func(transform.BaseRelocEntry) error {
		called = true
		return nil
	})
	if err != nil {
		t.Errorf("empty directory: want nil error, got %v", err)
	}
	if called {
		t.Error("callback fired despite empty reloc directory")
	}
}

func TestWalkBaseRelocs_PropagatesCallbackError(t *testing.T) {
	pe := peWithRelocs(t)
	sentinel := errors.New("stop")
	count := 0
	err := transform.WalkBaseRelocs(pe, func(transform.BaseRelocEntry) error {
		count++
		if count == 2 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("got %v, want sentinel error", err)
	}
	if count != 2 {
		t.Errorf("callback called %d times, want 2 (walk should stop)", count)
	}
}

func TestWalkBaseRelocs_RejectsBogusBlockSize(t *testing.T) {
	pe := peWithRelocs(t)
	// blockSize=4 (less than the 8-byte header) should error.
	const blockFileOff = 0x400 + 0x10
	binary.LittleEndian.PutUint32(pe[blockFileOff+4:], 4)
	err := transform.WalkBaseRelocs(pe, func(transform.BaseRelocEntry) error { return nil })
	if err == nil {
		t.Error("blockSize=4: want error, got nil")
	}
}

// TestWalkBaseRelocs_RealWinhello sanity-checks the walker
// against the real winhello fixture: it must visit at least
// some DIR64 entries (a Go-built static binary has hundreds).
func TestWalkBaseRelocs_RealWinhello(t *testing.T) {
	path := filepath.Join("..", "testdata", "winhello.exe")
	pe, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture missing (%v); build via testdata/Makefile", err)
	}
	var (
		total  int
		dir64s int
	)
	err = transform.WalkBaseRelocs(pe, func(e transform.BaseRelocEntry) error {
		total++
		if e.Type == transform.RelTypeDir64 {
			dir64s++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkBaseRelocs: %v", err)
	}
	if total == 0 {
		t.Fatal("real PE produced 0 reloc entries — directory empty?")
	}
	if dir64s < 10 {
		t.Errorf("only %d DIR64 entries on a Go static-PIE; expected hundreds", dir64s)
	}
	t.Logf("winhello.exe: %d total reloc entries (%d DIR64, %d padding/other)",
		total, dir64s, total-dir64s)
}
