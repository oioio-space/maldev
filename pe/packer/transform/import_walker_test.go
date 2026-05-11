package transform_test

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// peWith2Imports builds a synthetic PE with one section
// containing a tiny IMPORT directory: 2 descriptors (kernel32,
// user32), each with 2 imports (one by-name, one by-ordinal),
// then a zero terminator. Just enough to exercise every code
// path in WalkImportDirectoryRVAs.
//
// File layout inside section 0 (RVA 0x1000, file 0x400, size 0x400):
//
//	+0x10  descriptor[0] kernel32:
//	          OFT  → 0x100 (RVA 0x1100)
//	          Name → 0x80  (RVA 0x1080) "kernel32.dll\0"
//	          FT   → 0x180 (RVA 0x1180)
//	+0x24  descriptor[1] user32:
//	          OFT  → 0x140 (RVA 0x1140)
//	          Name → 0x90  (RVA 0x1090) "user32.dll\0"
//	          FT   → 0x1c0 (RVA 0x11c0)
//	+0x38  zero descriptor (terminator)
//
//	+0x80  "kernel32.dll\0"
//	+0x90  "user32.dll\0"
//
//	+0x100 ILT[0]: 0x00000000_00000200 (by-name → IMAGE_IMPORT_BY_NAME at RVA 0x1200)
//	+0x108 ILT[0]: 0x80000000_00000005 (by-ordinal #5)
//	+0x110 ILT[0]: 0x00000000_00000000 (terminator)
//
//	+0x140 ILT[1]: 0x00000000_00000220 (by-name → RVA 0x1220)
//	+0x148 ILT[1]: 0x80000000_0000000a (by-ordinal #10)
//	+0x150 ILT[1]: 0x00000000_00000000 (terminator)
//
//	(IATs at 0x180 and 0x1c0 mirror the corresponding ILTs)
//
//	+0x200 IMAGE_IMPORT_BY_NAME{Hint=0, Name="GetProcAddress\0"}
//	+0x220 IMAGE_IMPORT_BY_NAME{Hint=0, Name="MessageBoxA\0"}
func peWith2Imports(t *testing.T) []byte {
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
		bufSize       = 0x1000
		sec0VA        = 0x1000
		sec0RawOff    = 0x400
		sec0RawSize   = 0x400
		// Import directory inside section 0
		importDirRVA  = 0x1010
		importDirSize = 0x14*3 + 0 // 2 descriptors + 1 terminator
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

	// IMPORT DataDirectory entry
	importEntry := optOff + transform.OptDataDirsStart + 1*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(out[importEntry:], importDirRVA)
	binary.LittleEndian.PutUint32(out[importEntry+4:], importDirSize)

	// Section 0 header
	hdrOff := secTableOff
	copy(out[hdrOff:], ".text")
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualSizeOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualAddressOffset:], sec0VA)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecSizeOfRawDataOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecPointerToRawDataOffset:], sec0RawOff)

	// Helper: write a uint32/uint64 at section-relative offset.
	put32 := func(secOff uint32, v uint32) {
		binary.LittleEndian.PutUint32(out[sec0RawOff+secOff:], v)
	}
	put64 := func(secOff uint32, v uint64) {
		binary.LittleEndian.PutUint64(out[sec0RawOff+secOff:], v)
	}
	putStr := func(secOff uint32, s string) {
		copy(out[sec0RawOff+secOff:], s)
		out[sec0RawOff+secOff+uint32(len(s))] = 0
	}

	// Descriptor[0] @ section 0x10 (matches importDirRVA - sec0VA).
	put32(0x10+0x00, sec0VA+0x100) // OFT → 0x1100
	put32(0x10+0x0C, sec0VA+0x80)  // Name → 0x1080
	put32(0x10+0x10, sec0VA+0x180) // FT → 0x1180
	// Descriptor[1] @ section 0x24
	put32(0x24+0x00, sec0VA+0x140) // OFT → 0x1140
	put32(0x24+0x0C, sec0VA+0x90)  // Name → 0x1090
	put32(0x24+0x10, sec0VA+0x1c0) // FT → 0x11c0
	// Descriptor[2] = terminator (already zero from make())

	// DLL name strings
	putStr(0x80, "kernel32.dll")
	putStr(0x90, "user32.dll")

	// ILT[0] @ section 0x100
	put64(0x100, uint64(sec0VA+0x200)) // by-name → IMAGE_IMPORT_BY_NAME at 0x1200
	put64(0x108, 0x8000000000000005)   // by-ordinal #5
	put64(0x110, 0)                    // terminator
	// IAT[0] @ section 0x180 — mirror ILT[0]
	put64(0x180, uint64(sec0VA+0x200))
	put64(0x188, 0x8000000000000005)
	put64(0x190, 0)
	// ILT[1] @ section 0x140
	put64(0x140, uint64(sec0VA+0x220))
	put64(0x148, 0x800000000000000a)
	put64(0x150, 0)
	// IAT[1] @ section 0x1c0 — mirror ILT[1]
	put64(0x1c0, uint64(sec0VA+0x220))
	put64(0x1c8, 0x800000000000000a)
	put64(0x1d0, 0)

	// IMAGE_IMPORT_BY_NAME entries
	put32(0x200, 0) // hint = 0 (uint16, but 4-byte zero is fine)
	putStr(0x202, "GetProcAddress")
	put32(0x220, 0)
	putStr(0x222, "MessageBoxA")
	return out
}

func TestWalkImportDirectoryRVAs_VisitsExpectedFields(t *testing.T) {
	pe := peWith2Imports(t)
	var visited []uint32
	err := transform.WalkImportDirectoryRVAs(pe, func(off uint32) error {
		visited = append(visited, off)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkImportDirectoryRVAs: %v", err)
	}
	// Expected count:
	//   2 descriptors × 3 RVA fields (OFT/Name/FT) = 6
	//   2 ILTs × 1 by-name entry each              = 2
	//   2 IATs × 1 by-name entry each              = 2
	// Total = 10
	if got := len(visited); got != 10 {
		t.Errorf("visited %d offsets, want 10 (2 descs × 3 RVA fields + 2 ILTs × 1 byname + 2 IATs × 1 byname)", got)
	}
}

func TestWalkImportDirectoryRVAs_DescriptorRVAValuesMatchInput(t *testing.T) {
	pe := peWith2Imports(t)
	const sec0RawOff = 0x400
	wantRVAs := map[uint32]bool{
		0x1100: true, 0x1080: true, 0x1180: true, // descriptor[0] OFT/Name/FT
		0x1140: true, 0x1090: true, 0x11c0: true, // descriptor[1] OFT/Name/FT
		0x1200: true, // ILT[0] by-name
		0x1220: true, // ILT[1] by-name
	}
	got := map[uint32]bool{}
	err := transform.WalkImportDirectoryRVAs(pe, func(off uint32) error {
		rva := binary.LittleEndian.Uint32(pe[off:])
		got[rva] = true
		return nil
	})
	if err != nil {
		t.Fatalf("WalkImportDirectoryRVAs: %v", err)
	}
	// Sanity-check that all expected RVAs were observed (each
	// appears at least once — IAT mirrors ILT so 0x1200/0x1220
	// each show twice, the map collapses).
	for want := range wantRVAs {
		if !got[want] {
			t.Errorf("missing RVA 0x%x in walker yield", want)
		}
	}
	_ = sec0RawOff
}

func TestWalkImportDirectoryRVAs_SkipsByOrdinalThunks(t *testing.T) {
	pe := peWith2Imports(t)
	count := 0
	err := transform.WalkImportDirectoryRVAs(pe, func(off uint32) error {
		// Read the uint64 at off — if the high bit is set, the
		// walker yielded an ordinal entry by mistake.
		if int(off)+8 <= len(pe) {
			v := binary.LittleEndian.Uint64(pe[off:])
			if v&0x8000000000000000 != 0 {
				t.Errorf("yielded by-ordinal thunk at file 0x%x (value 0x%x)", off, v)
			}
		}
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("WalkImportDirectoryRVAs: %v", err)
	}
	if count == 0 {
		t.Fatal("walker yielded zero entries — fixture broken?")
	}
}

func TestWalkImportDirectoryRVAs_NoDirectoryReturnsNil(t *testing.T) {
	pe := peWith2Imports(t)
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	importEntry := optOff + transform.OptDataDirsStart + 1*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(pe[importEntry:], 0)
	binary.LittleEndian.PutUint32(pe[importEntry+4:], 0)
	called := false
	err := transform.WalkImportDirectoryRVAs(pe, func(uint32) error {
		called = true
		return nil
	})
	if err != nil {
		t.Errorf("empty IMPORT directory: want nil, got %v", err)
	}
	if called {
		t.Error("callback fired despite empty directory")
	}
}

func TestWalkImportDirectoryRVAs_PropagatesCallbackError(t *testing.T) {
	pe := peWith2Imports(t)
	sentinel := errors.New("stop")
	count := 0
	err := transform.WalkImportDirectoryRVAs(pe, func(uint32) error {
		count++
		if count == 3 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("got %v, want sentinel", err)
	}
	if count != 3 {
		t.Errorf("callback called %d times, want 3 (walk should stop on error)", count)
	}
}

// TestWalkImportDirectoryRVAs_RealWinhello sanity-checks the
// walker against the real winhello.exe fixture: it must visit a
// non-trivial number of RVAs (a Go static-PIE imports kernel32 +
// other DLLs with dozens of functions).
func TestWalkImportDirectoryRVAs_RealWinhello(t *testing.T) {
	path := filepath.Join("..", "testdata", "winhello.exe")
	pe, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture missing (%v); build via testdata/Makefile", err)
	}
	count := 0
	err = transform.WalkImportDirectoryRVAs(pe, func(uint32) error {
		count++
		return nil
	})
	if err != nil {
		t.Fatalf("WalkImportDirectoryRVAs: %v", err)
	}
	if count < 10 {
		t.Errorf("only %d import RVAs on a Go static-PIE; expected dozens", count)
	}
	t.Logf("winhello.exe: %d import-directory RVAs to patch under VA shift", count)
}
