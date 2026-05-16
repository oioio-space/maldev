package transform

import (
	"encoding/binary"
	"fmt"
)

// BuildDirectRVAExportData builds an IMAGE_EXPORT_DIRECTORY + one
// named export whose AddressOfFunctions[0] slot points directly at
// `entryRVA` (a code RVA), not at a forwarder string.
//
// Counterpart of [github.com/oioio-space/maldev/pe/dllproxy.BuildExportData]:
// dllproxy emits forwarder-only export tables where each
// AddressOfFunctions slot points at an ASCII forwarder ("kernel32.Sleep");
// this builder emits a real DLL export where the slot points at code
// inside the same image. Used by the converted-DLL packer to expose
// `RunWithArgs` from the appended stub section.
//
// Layout (offsets within the returned blob):
//
//	0x00  IMAGE_EXPORT_DIRECTORY (40 B)
//	0x28  AddressOfFunctions[0]   = entryRVA               (4 B)
//	0x2C  AddressOfNames[0]       = sectionRVA + name-off  (4 B)
//	0x30  AddressOfNameOrdinals[0]= 0                      (2 B)
//	0x32  module-name string + NUL
//	      export-name string + NUL
//
// Caller is responsible for placing the bytes at `sectionRVA` (e.g.,
// via [AppendExportSection]) and pointing
// DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] at (sectionRVA, size).
// [AppendExportSection] does both in one step.
//
// Returns (bytes, size).
func BuildDirectRVAExportData(moduleName, exportName string, entryRVA, sectionRVA uint32) ([]byte, uint32, error) {
	if moduleName == "" || exportName == "" {
		return nil, 0, fmt.Errorf("transform: BuildDirectRVAExportData: moduleName and exportName must be non-empty")
	}
	const (
		exportDirSz     = 40
		addrFuncsOffset = uint32(exportDirSz)        // 40
		addrNamesOffset = addrFuncsOffset + 4        // 44
		addrOrdsOffset  = addrNamesOffset + 4        // 48
		stringsOffset   = addrOrdsOffset + 2         // 50
	)

	moduleBytes := append([]byte(moduleName), 0)
	exportBytes := append([]byte(exportName), 0)

	moduleNameRVA := sectionRVA + stringsOffset
	exportNameRVA := moduleNameRVA + uint32(len(moduleBytes))

	out := make([]byte, stringsOffset)
	binary.LittleEndian.PutUint32(out[12:], moduleNameRVA)              // Name
	binary.LittleEndian.PutUint32(out[16:], 1)                          // Base (ordinal of first export)
	binary.LittleEndian.PutUint32(out[20:], 1)                          // NumberOfFunctions
	binary.LittleEndian.PutUint32(out[24:], 1)                          // NumberOfNames
	binary.LittleEndian.PutUint32(out[28:], sectionRVA+addrFuncsOffset) // AddressOfFunctions
	binary.LittleEndian.PutUint32(out[32:], sectionRVA+addrNamesOffset) // AddressOfNames
	binary.LittleEndian.PutUint32(out[36:], sectionRVA+addrOrdsOffset)  // AddressOfNameOrdinals
	binary.LittleEndian.PutUint32(out[addrFuncsOffset:], entryRVA)      // AddressOfFunctions[0] = code RVA
	binary.LittleEndian.PutUint32(out[addrNamesOffset:], exportNameRVA) // AddressOfNames[0]
	binary.LittleEndian.PutUint16(out[addrOrdsOffset:], 0)              // AddressOfNameOrdinals[0]

	out = append(out, moduleBytes...)
	out = append(out, exportBytes...)
	return out, uint32(len(out)), nil
}
