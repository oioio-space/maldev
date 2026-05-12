package transform_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// peWithResources builds a synthetic PE carrying a 2-level
// resource tree (root → 1 type → 2 lang leaves) for the walker
// tests. Layout inside section 0 (RVA 0x1000, file 0x400):
//
//	+0x10  IMAGE_RESOURCE_DIRECTORY (root)  : 0 named, 1 id
//	+0x18  IMAGE_RESOURCE_DIRECTORY_ENTRY   : id=10, OffsetToData=0x20|HIGH (subdir)
//	+0x30  IMAGE_RESOURCE_DIRECTORY (sub)   : 0 named, 2 id
//	+0x38  IMAGE_RESOURCE_DIRECTORY_ENTRY   : id=1,  OffsetToData=0x60 (leaf)
//	+0x40  IMAGE_RESOURCE_DIRECTORY_ENTRY   : id=2,  OffsetToData=0x70 (leaf)
//	+0x60  IMAGE_RESOURCE_DATA_ENTRY        : OffsetToData=0x1234 (RVA — yielded)
//	+0x70  IMAGE_RESOURCE_DATA_ENTRY        : OffsetToData=0x5678 (RVA — yielded)
func peWithResources(t *testing.T) []byte {
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
		sec0RawSize   = 0x200
		// Resource directory inside section 0 at section-relative 0x10.
		resDirRVA = 0x1010
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

	// DataDirectory[2] RESOURCE
	resDirEntry := optOff + transform.OptDataDirsStart + 2*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(out[resDirEntry:], resDirRVA)
	binary.LittleEndian.PutUint32(out[resDirEntry+4:], 0x100)

	// Section 0 header
	hdrOff := secTableOff
	copy(out[hdrOff:], ".rsrc")
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualSizeOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualAddressOffset:], sec0VA)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecSizeOfRawDataOffset:], sec0RawSize)
	binary.LittleEndian.PutUint32(out[hdrOff+transform.SecPointerToRawDataOffset:], sec0RawOff)

	put32 := func(off uint32, v uint32) {
		binary.LittleEndian.PutUint32(out[sec0RawOff+off:], v)
	}
	put16 := func(off uint32, v uint16) {
		binary.LittleEndian.PutUint16(out[sec0RawOff+off:], v)
	}
	// Layout (all section-relative offsets; root @ 0x10):
	//   0x10..0x1F  root IMAGE_RESOURCE_DIRECTORY (16 B header)
	//   0x20..0x27  root entry (id=10, OffsetToData=0x20|HIGH → subdir)
	//   0x30..0x3F  subdir IMAGE_RESOURCE_DIRECTORY (16 B header)
	//   0x40..0x47  subdir entry 1 (id=1, OffsetToData=0x60 → leaf 1)
	//   0x48..0x4F  subdir entry 2 (id=2, OffsetToData=0x70 → leaf 2)
	//   0x70..0x7F  IMAGE_RESOURCE_DATA_ENTRY 1 (OffsetToData=0x1234)
	//   0x80..0x8F  IMAGE_RESOURCE_DATA_ENTRY 2 (OffsetToData=0x5678)
	// Note: subdir entry OffsetToData values (0x60, 0x70) are
	// RELATIVE TO ROOT (section 0x10), so leaf 1 sits at section
	// 0x10+0x60=0x70 and leaf 2 at section 0x10+0x70=0x80.
	put16(0x10+0x0C, 0)
	put16(0x10+0x0E, 1)
	put32(0x20+0x00, 10)
	put32(0x20+0x04, 0x20|0x80000000)
	put16(0x30+0x0C, 0)
	put16(0x30+0x0E, 2)
	put32(0x40+0x00, 1)
	put32(0x40+0x04, 0x60)
	put32(0x48+0x00, 2)
	put32(0x48+0x04, 0x70)
	put32(0x70+0x00, 0x1234) // leaf 1: RVA = 0x1234
	put32(0x70+0x04, 100)
	put32(0x80+0x00, 0x5678) // leaf 2: RVA = 0x5678
	put32(0x80+0x04, 200)
	return out
}

func TestWalkResourceDirectoryRVAs_VisitsLeafRVAsOnly(t *testing.T) {
	pe := peWithResources(t)
	var visited []uint32
	err := transform.WalkResourceDirectoryRVAs(pe, func(off uint32) error {
		v := binary.LittleEndian.Uint32(pe[off:])
		visited = append(visited, v)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkResourceDirectoryRVAs: %v", err)
	}
	want := []uint32{0x1234, 0x5678}
	if len(visited) != len(want) {
		t.Fatalf("visited %d, want %d", len(visited), len(want))
	}
	for i, v := range visited {
		if v != want[i] {
			t.Errorf("visited[%d] = 0x%x, want 0x%x", i, v, want[i])
		}
	}
}

func TestWalkResourceDirectoryRVAs_NoDirectoryReturnsNil(t *testing.T) {
	pe := peWithResources(t)
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	resDir := optOff + transform.OptDataDirsStart + 2*transform.OptDataDirEntrySize
	binary.LittleEndian.PutUint32(pe[resDir:], 0)
	binary.LittleEndian.PutUint32(pe[resDir+4:], 0)
	called := false
	err := transform.WalkResourceDirectoryRVAs(pe, func(uint32) error {
		called = true
		return nil
	})
	if err != nil {
		t.Errorf("empty RESOURCE: want nil, got %v", err)
	}
	if called {
		t.Error("callback fired despite empty directory")
	}
}

func TestWalkResourceDirectoryRVAs_PropagatesCallbackError(t *testing.T) {
	pe := peWithResources(t)
	sentinel := errors.New("stop")
	count := 0
	err := transform.WalkResourceDirectoryRVAs(pe, func(uint32) error {
		count++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("got %v, want sentinel", err)
	}
	if count != 1 {
		t.Errorf("callback called %d times, want 1", count)
	}
}
