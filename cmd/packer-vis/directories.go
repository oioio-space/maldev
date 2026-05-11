package main

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// runDirectories prints every populated DataDirectory of a PE.
// Tells an operator at-a-glance which packer features touch the
// binary: IMPORT-walker only? Or also EXPORT (DLL packing)?
// Or RESOURCE (FindResource consumers)? Used today (2026-05-11)
// to discover Go static-PIE binaries populate ONLY 4 directories
// (IMPORT/EXCEPTION/BASERELOC/IAT) — letting the walker-suite
// roadmap shrink dramatically.
//
// Companion to `packer-vis sections`. Together they answer
// "what's in this PE that the packer needs to know about" without
// reaching for dumpbin or Sysinternals.
var dirNames = [...]string{
	"EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY",
	"BASERELOC", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS",
	"LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT",
	"COM_DESCRIPTOR", "RESERVED",
}

func runDirectories(path string) int {
	pe, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "packer-vis directories: %v\n", err)
		return 1
	}
	if len(pe) < int(transform.PEELfanewOffset)+4 {
		fmt.Fprintln(os.Stderr, "packer-vis directories: file too short")
		return 1
	}
	peOff := binary.LittleEndian.Uint32(pe[transform.PEELfanewOffset:])
	if int(peOff)+4 > len(pe) || binary.LittleEndian.Uint32(pe[peOff:]) != 0x00004550 {
		fmt.Fprintln(os.Stderr, "packer-vis directories: not a PE file")
		return 1
	}
	optOff := peOff + transform.PESignatureSize + transform.PECOFFHdrSize
	fmt.Printf("file: %s (%d bytes)\n\n", path, len(pe))
	fmt.Printf("%-3s %-16s %-12s %s\n", "#", "Directory", "RVA", "Size")
	for i := 0; i < 16; i++ {
		entryOff := optOff + transform.OptDataDirsStart + uint32(i*transform.OptDataDirEntrySize)
		if int(entryOff)+transform.OptDataDirEntrySize > len(pe) {
			break
		}
		rva := binary.LittleEndian.Uint32(pe[entryOff:])
		size := binary.LittleEndian.Uint32(pe[entryOff+4:])
		mark := "  "
		if rva != 0 || size != 0 {
			mark = "✓ "
		}
		fmt.Printf("%s%-2d %-16s 0x%-10x %d\n", mark, i, dirNames[i], rva, size)
	}
	return 0
}
