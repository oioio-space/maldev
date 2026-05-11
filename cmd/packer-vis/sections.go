package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// runSections dumps the section table + COFF symbol-table pointer
// of a PE file. Companion to the Phase 2-F transforms — lets an
// operator see what RandomizeExistingSectionNames /
// RandomizeJunkSections / RandomizePEFileOrder actually changed
// between two packs without spinning up a hex editor.
//
// Output one row per section: index, name, VirtualAddress,
// VirtualSize, PointerToRawData, SizeOfRawData, Characteristics.
// Followed by COFF.PointerToSymbolTable + NumberOfSymbols (these
// MUST track .symtab moves under PermuteSectionFileOrder; the
// fields are surfaced so operators can spot regressions visually).
func runSections(path string) int {
	pe, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "packer-vis sections: %v\n", err)
		return 1
	}
	if len(pe) < int(transform.PEELfanewOffset)+4 {
		fmt.Fprintln(os.Stderr, "packer-vis sections: file too short for e_lfanew")
		return 1
	}
	peOff := binary.LittleEndian.Uint32(pe[transform.PEELfanewOffset:])
	if int(peOff)+4 > len(pe) || binary.LittleEndian.Uint32(pe[peOff:]) != 0x00004550 {
		fmt.Fprintln(os.Stderr, "packer-vis sections: not a PE file (missing PE signature)")
		return 1
	}
	coffOff := peOff + transform.PESignatureSize
	numSections := binary.LittleEndian.Uint16(pe[coffOff+transform.COFFNumSectionsOffset:])
	sizeOfOptHdr := binary.LittleEndian.Uint16(pe[coffOff+transform.COFFSizeOfOptHdrOffset:])
	pSym := binary.LittleEndian.Uint32(pe[coffOff+0x08:])
	nSym := binary.LittleEndian.Uint32(pe[coffOff+0x0C:])
	secTableOff := coffOff + transform.PECOFFHdrSize + uint32(sizeOfOptHdr)

	fmt.Printf("file: %s (%d bytes)\n", path, len(pe))
	fmt.Printf("NumberOfSections: %d\n", numSections)
	fmt.Printf("COFF.PointerToSymbolTable: 0x%x  NumberOfSymbols: %d\n\n", pSym, nSym)
	fmt.Printf("%-3s  %-10s  %-10s  %-10s  %-10s  %-10s  %s\n",
		"#", "Name", "VA", "VirtSize", "RawOff", "RawSize", "Characteristics")
	for i := uint16(0); i < numSections; i++ {
		hdr := secTableOff + uint32(i)*transform.PESectionHdrSize
		var name [8]byte
		copy(name[:], pe[hdr:hdr+8])
		va := binary.LittleEndian.Uint32(pe[hdr+transform.SecVirtualAddressOffset:])
		vs := binary.LittleEndian.Uint32(pe[hdr+transform.SecVirtualSizeOffset:])
		rawOff := binary.LittleEndian.Uint32(pe[hdr+transform.SecPointerToRawDataOffset:])
		rawSize := binary.LittleEndian.Uint32(pe[hdr+transform.SecSizeOfRawDataOffset:])
		char := binary.LittleEndian.Uint32(pe[hdr+transform.SecCharacteristicsOffset:])
		fmt.Printf("%-3d  %-10s  0x%08x  0x%08x  0x%08x  0x%08x  0x%08x %s\n",
			i, sectionName(name), va, vs, rawOff, rawSize, char, decodeChar(char))
	}
	return 0
}

// sectionName trims trailing NULs from a PE section's 8-byte name.
func sectionName(name [8]byte) string {
	for i, b := range name {
		if b == 0 {
			return string(name[:i])
		}
	}
	return string(name[:])
}

// decodeChar produces a short symbolic summary of the most-common
// IMAGE_SCN_* characteristic bits (CODE/INITDATA/UNINITDATA + RWX).
func decodeChar(c uint32) string {
	out := "["
	if c&0x00000020 != 0 {
		out += "CODE "
	}
	if c&0x00000040 != 0 {
		out += "DATA "
	}
	if c&0x00000080 != 0 {
		out += "BSS "
	}
	if c&0x40000000 != 0 {
		out += "R"
	}
	if c&0x80000000 != 0 {
		out += "W"
	}
	if c&0x20000000 != 0 {
		out += "X"
	}
	out += "]"
	return out
}
