package transform

// PE32+ layout constants exported for sibling packages in
// pe/packer/ that share section-table manipulation logic. Values
// come from the Microsoft PE/COFF Specification Rev 12.0; the
// unexported near-duplicates inside pe.go remain for in-package
// brevity.
//
// Keep this set deliberately small — only the fields the cover
// layer (and any future PE writer) reads or writes are promoted.
// New consumers should add only what they actually use rather than
// mirroring every constant in pe.go.
const (
	// PEELfanewOffset is the file offset of e_lfanew inside the
	// DOS stub — the dword that points at the PE\0\0 signature.
	PEELfanewOffset = 0x3C

	// PESignatureSize is the byte length of the PE\0\0 signature.
	PESignatureSize = 4

	// PECOFFHdrSize is the byte length of the COFF File Header
	// that follows the PE signature.
	PECOFFHdrSize = 20

	// PESectionHdrSize is the byte length of one section header.
	PESectionHdrSize = 40

	// COFFNumSectionsOffset is the file offset of NumberOfSections
	// inside the COFF header.
	COFFNumSectionsOffset = 0x02

	// COFFSizeOfOptHdrOffset is the file offset of
	// SizeOfOptionalHeader inside the COFF header.
	COFFSizeOfOptHdrOffset = 0x10

	// OptSectionAlignOffset is the file offset of SectionAlignment
	// inside the PE32+ Optional Header.
	OptSectionAlignOffset = 0x20

	// OptFileAlignOffset is the file offset of FileAlignment
	// inside the PE32+ Optional Header.
	OptFileAlignOffset = 0x24

	// OptSizeOfImageOffset is the file offset of SizeOfImage.
	OptSizeOfImageOffset = 0x38

	// SecVirtualSizeOffset is the file offset of VirtualSize
	// inside a section header.
	SecVirtualSizeOffset = 0x08

	// SecVirtualAddressOffset is the file offset of VirtualAddress.
	SecVirtualAddressOffset = 0x0C

	// SecSizeOfRawDataOffset is the file offset of SizeOfRawData.
	SecSizeOfRawDataOffset = 0x10

	// SecPointerToRawDataOffset is the file offset of
	// PointerToRawData.
	SecPointerToRawDataOffset = 0x14

	// SecCharacteristicsOffset is the file offset of
	// Characteristics inside a section header.
	SecCharacteristicsOffset = 0x24

	// ScnCntInitData is IMAGE_SCN_CNT_INITIALIZED_DATA.
	ScnCntInitData uint32 = 0x00000040

	// ScnMemRead is IMAGE_SCN_MEM_READ.
	ScnMemRead uint32 = 0x40000000

	// ScnMemReadInitData is the OR of [ScnCntInitData] and
	// [ScnMemRead] — the read-only-data Characteristics value
	// that cover-layer junk sections carry.
	ScnMemReadInitData uint32 = ScnCntInitData | ScnMemRead
)
