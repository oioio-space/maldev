// Package morph provides UPX header mutation for PE files.
package morph

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/oioio-space/maldev/random"
	"github.com/saferwall/pe"
)

// sectionHeaderOffset returns the file offset of the i-th section header's
// Name field in peData. The layout is:
//
//	PE offset at file offset 0x3C (4 bytes, LE)
//	COFF header starts at PE_offset + 4 (after "PE\0\0" signature)
//	SizeOfOptionalHeader is at COFF+16 (2 bytes, LE)
//	Section table starts at COFF + 20 + SizeOfOptionalHeader
//	Each section header is 40 bytes; Name is the first 8 bytes.
func sectionHeaderOffset(peData []byte, index int) uint32 {
	peOffset := binary.LittleEndian.Uint32(peData[0x3C:])
	coffStart := peOffset + 4
	sizeOfOptHdr := binary.LittleEndian.Uint16(peData[coffStart+16:])
	sectionTableStart := coffStart + 20 + uint32(sizeOfOptHdr)
	return sectionTableStart + uint32(index)*40
}

// numSectionsAndTableStart reads the COFF header to find how many section
// headers follow and where the section table begins. Reading the raw bytes
// avoids saferwall/pe's Fast-mode quirk that occasionally leaves
// pefile.Sections empty on UPX 4.x binaries (where the library's
// overlay detection heuristic short-circuits before section parsing).
func numSectionsAndTableStart(peData []byte) (num uint16, tableStart uint32, err error) {
	if len(peData) < 0x40 {
		return 0, 0, fmt.Errorf("PE too small: %d bytes", len(peData))
	}
	peOffset := binary.LittleEndian.Uint32(peData[0x3C:])
	if int(peOffset)+24 > len(peData) {
		return 0, 0, fmt.Errorf("invalid PE offset: %#x", peOffset)
	}
	coffStart := peOffset + 4
	num = binary.LittleEndian.Uint16(peData[coffStart+2:])
	sizeOfOptHdr := binary.LittleEndian.Uint16(peData[coffStart+16:])
	tableStart = coffStart + 20 + uint32(sizeOfOptHdr)
	return num, tableStart, nil
}

// UPXMorph replaces UPX section names in a packed PE with random bytes
// to prevent automatic unpacking and change the file hash.
// If the file is not UPX-packed, the data is returned unchanged.
//
// Implementation note: we parse section headers from raw bytes rather than
// via saferwall/pe. The library's Fast-mode Sections slice is empty on
// UPX 4.x binaries (its overlay-detection heuristic short-circuits before
// section parsing), which silently turned the previous implementation
// into a no-op. A direct COFF walk is also faster and keeps the function
// dependency-free.
func UPXMorph(peData []byte) ([]byte, error) {
	nSec, tableStart, err := numSectionsAndTableStart(peData)
	if err != nil {
		return peData, err
	}
	for i := 0; i < int(nSec); i++ {
		off := int(tableStart) + i*40
		if off+8 > len(peData) {
			break
		}
		name := string(bytes.TrimRight(peData[off:off+8], "\x00"))
		if strings.Contains(name, "UPX") {
			s, rerr := random.String(8)
			if rerr != nil {
				return peData, fmt.Errorf("generate random name: %w", rerr)
			}
			copy(peData[off:off+8], []byte(s))
		}
	}
	return peData, nil
}

// UPXFix restores the original UPX section names (UPX0, UPX1, UPX2) in a
// packed PE file by writing them to the section header Name fields.
func UPXFix(peData []byte) ([]byte, error) {
	pefile, err := pe.NewBytes(peData, &pe.Options{Fast: true})
	if err != nil {
		return peData, err
	}
	defer pefile.Close()

	err = pefile.Parse()
	if err != nil {
		return peData, err
	}

	numSections := len(pefile.Sections)
	if numSections < 3 {
		return peData, fmt.Errorf("expected at least 3 sections for UPX binary, got %d", numSections)
	}

	// Standard UPX-packed binaries have 3 sections: UPX0, UPX1, UPX2.
	upxNames := []string{"UPX0", "UPX1", "UPX2"}
	for i, name := range upxNames {
		offset := sectionHeaderOffset(peData, i)
		var nameBuf [8]byte
		copy(nameBuf[:], name)
		copy(peData[offset:offset+8], nameBuf[:])
	}

	return peData, nil
}
