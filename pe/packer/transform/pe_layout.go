package transform

import (
	"encoding/binary"
	"fmt"
)

// peLayout caches the per-region offsets every Phase 2 patcher
// resolves out of a PE32+ buffer (e_lfanew → COFF → Optional →
// section table). Computed once per call by parsePELayout; readers
// rely on the bounds checks done at parse time and may index into
// the buffer with the cached offsets without re-validating.
type peLayout struct {
	peOff        uint32
	coffOff      uint32
	optOff       uint32
	sizeOfOptHdr uint16
	secTableOff  uint32
	numSections  uint16
}

// parsePELayout validates DOS magic, e_lfanew, the PE signature,
// and the COFF / Optional / section-table bounds, then returns the
// resolved offsets. Patchers in this package call it before
// touching header bytes so each one shares the same bounds-check
// vocabulary instead of re-implementing the walk.
func parsePELayout(pe []byte) (peLayout, error) {
	if len(pe) < int(PEELfanewOffset)+4 {
		return peLayout{}, fmt.Errorf("transform: PE too short for e_lfanew")
	}
	peOff := binary.LittleEndian.Uint32(pe[PEELfanewOffset : PEELfanewOffset+4])
	coffOff := peOff + PESignatureSize
	if int(coffOff)+PECOFFHdrSize > len(pe) {
		return peLayout{}, fmt.Errorf("transform: PE too short for COFF header")
	}
	sizeOfOptHdr := binary.LittleEndian.Uint16(pe[coffOff+COFFSizeOfOptHdrOffset : coffOff+COFFSizeOfOptHdrOffset+2])
	optOff := coffOff + PECOFFHdrSize
	if int(optOff)+int(sizeOfOptHdr) > len(pe) {
		return peLayout{}, fmt.Errorf("transform: PE too short for Optional Header (%d)", sizeOfOptHdr)
	}
	numSections := binary.LittleEndian.Uint16(pe[coffOff+COFFNumSectionsOffset : coffOff+COFFNumSectionsOffset+2])
	secTableOff := optOff + uint32(sizeOfOptHdr)
	if int(secTableOff)+int(numSections)*PESectionHdrSize > len(pe) {
		return peLayout{}, fmt.Errorf("transform: PE too short for section table (%d sections)", numSections)
	}
	return peLayout{
		peOff:        peOff,
		coffOff:      coffOff,
		optOff:       optOff,
		sizeOfOptHdr: sizeOfOptHdr,
		secTableOff:  secTableOff,
		numSections:  numSections,
	}, nil
}
