package runtime

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer"
)

// Sentinels surfaced by [LoadPE] / [Prepare].
var (
	// ErrUnsupportedArch fires when the packed PE is not x64
	// (PE32+ Magic = 0x20B). x86 and ARM64 are out of scope.
	ErrUnsupportedArch = errors.New("packer/runtime: only PE32+ (x64) is supported")

	// ErrNotEXE fires when the input is a DLL or driver. DLLs
	// need DllMain calling and a HINSTANCE handle; not yet
	// supported.
	ErrNotEXE = errors.New("packer/runtime: only EXE images are supported (no DLLs)")

	// ErrTLSCallbacks fires when the loaded PE declares TLS
	// callbacks (IMAGE_DIRECTORY_ENTRY_TLS non-zero). Many
	// production binaries use them; supporting requires walking
	// the TLS directory and calling each callback per
	// DLL_PROCESS_ATTACH semantics. Out of scope for v1.
	ErrTLSCallbacks = errors.New("packer/runtime: TLS callbacks not yet supported")

	// ErrBadPE fires when header parsing finds an inconsistency
	// (truncated headers, bad signature, impossible field
	// values). The wrapped error carries the specific gripe.
	ErrBadPE = errors.New("packer/runtime: malformed PE")
)

// PE constants used throughout the loader. Not exported because
// callers should never need them; debug/pe defines the same
// values but its struct shapes differ subtly from the on-wire
// format we walk here.
const (
	dosMagic      = 0x5A4D     // "MZ"
	peSignature   = 0x00004550 // "PE\0\0"
	pe32PlusMagic = 0x20B
	pe32Magic     = 0x10B

	machineAMD64 = 0x8664

	dllCharacteristic = 0x2000 // IMAGE_FILE_DLL

	dirImport     = 1
	dirReloc      = 5
	dirTLS        = 9
	dirIAT        = 12
	numDataDirs   = 16

	relTypeAbsolute = 0
	relTypeDir64    = 10
	relTypeHighLow  = 3
)

// PreparedImage is the result of [Prepare]: every step of the
// reflective load is done EXCEPT the actual jump to OEP. Useful
// for tests that want to inspect the in-memory image without
// running it.
//
// Do NOT call [PreparedImage.Run] outside of intended-execution
// contexts — once OEP is jumped, the original payload's behaviour
// is operator territory and the loader returns nothing.
type PreparedImage struct {
	// Base is the address where the image was mapped. Page-
	// aligned. Owned by the loader; freed by [PreparedImage.Free].
	Base uintptr

	// SizeOfImage is the on-disk OptionalHeader.SizeOfImage —
	// the total bytes the loader allocated for the mapping.
	SizeOfImage uint32

	// EntryPoint is the absolute address (Base + RVA) the OS
	// loader would jump to after CRT init. For an EXE this is
	// `mainCRTStartup` (or whatever the linker named it).
	EntryPoint uintptr

	// Imports records the (DLL, Function) pairs the loader
	// resolved for the IAT. Inspecting it lets tests confirm
	// the resolution layer worked without actually running the
	// payload.
	Imports []ResolvedImport
}

// ResolvedImport captures one IAT entry the loader populated.
type ResolvedImport struct {
	DLL      string
	Function string  // empty when imported by ordinal
	Ordinal  uint16  // non-zero only for ordinal imports
	Address  uintptr // resolved function address
}

// LoadPE is the operator-facing entry point. Decrypts `packed`
// with `key`, reflectively loads the resulting PE into the
// current process's memory, and (when the MALDEV_PACKER_RUN_E2E
// env var is set to "1") jumps to the entry point.
//
// Returns the [PreparedImage] for inspection regardless of
// whether the execute step ran. Caller takes ownership: defer
// [PreparedImage.Free] to release the mapping when done.
//
// Sentinels: [ErrUnsupportedArch], [ErrNotEXE], [ErrTLSCallbacks],
// [ErrBadPE], plus packer.Unpack's sentinels and any OS
// allocation / protection failures.
func LoadPE(packed, key []byte) (*PreparedImage, error) {
	pe, err := packer.Unpack(packed, key)
	if err != nil {
		return nil, fmt.Errorf("LoadPE: unpack: %w", err)
	}
	return Prepare(pe)
}

// Prepare runs every step of the reflective load except the
// jump to OEP. Splits out from [LoadPE] so callers that already
// have a decrypted PE / ELF buffer (test fixtures, alternate
// decrypt paths) can use the same loader.
//
// Format dispatch is by magic byte: "MZ" routes to the PE
// backend ([ErrBadPE] / [ErrUnsupportedArch] / [ErrNotEXE] /
// [ErrTLSCallbacks]); "\x7fELF" routes to the ELF backend
// ([ErrBadELF] / [ErrUnsupportedELFArch] / [ErrNotELFExec]).
// On a host platform that doesn't match the input format the
// backend returns [ErrFormatPlatformMismatch]; on a platform
// where the backend exists but isn't fully implemented yet
// (Linux ELF in Phase 1f Stage A) it returns [ErrNotImplemented].
func Prepare(input []byte) (*PreparedImage, error) {
	if len(input) < 4 {
		return nil, fmt.Errorf("%w: input < 4 bytes", ErrBadPE)
	}
	switch {
	case input[0] == 'M' && input[1] == 'Z':
		hdr, err := parseHeaders(input)
		if err != nil {
			return nil, err
		}
		return mapAndRelocate(input, hdr)
	case input[0] == elfMagic0 && input[1] == elfMagic1 &&
		input[2] == elfMagic2 && input[3] == elfMagic3:
		hdr, err := parseELFHeaders(input)
		if err != nil {
			return nil, err
		}
		return mapAndRelocateELF(input, hdr)
	default:
		return nil, fmt.Errorf("%w: unrecognised magic % x", ErrBadPE, input[:4])
	}
}

// peHeaders is everything we read out of the PE before mapping.
// Stays in unexported scope so the public surface is just
// [PreparedImage].
type peHeaders struct {
	machine            uint16
	numSections        uint16
	sizeOfOptionalHdr  uint16
	characteristics    uint16
	optMagic           uint16
	addressOfEntry     uint32
	imageBase          uint64
	sizeOfImage        uint32
	sizeOfHeaders      uint32
	dataDirs           [numDataDirs]dataDirectory
	sectionTableOffset int
}

type dataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type sectionEntry struct {
	Name             [8]byte
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  uint32
}

// parseHeaders walks the on-wire PE structure (DOS → PE
// signature → COFF File Header → Optional Header → Data
// Directories → Section Table). Strict: rejects malformed
// inputs early so we never allocate against a bad SizeOfImage.
func parseHeaders(pe []byte) (*peHeaders, error) {
	if len(pe) < 64 {
		return nil, fmt.Errorf("%w: input too small for DOS header", ErrBadPE)
	}
	if binary.LittleEndian.Uint16(pe[0:2]) != dosMagic {
		return nil, fmt.Errorf("%w: missing MZ signature", ErrBadPE)
	}
	peOff := int(binary.LittleEndian.Uint32(pe[60:64]))
	if peOff+24 > len(pe) {
		return nil, fmt.Errorf("%w: e_lfanew (%d) past end of buffer", ErrBadPE, peOff)
	}
	if binary.LittleEndian.Uint32(pe[peOff:peOff+4]) != peSignature {
		return nil, fmt.Errorf("%w: missing PE signature", ErrBadPE)
	}
	cof := peOff + 4
	h := &peHeaders{
		machine:           binary.LittleEndian.Uint16(pe[cof : cof+2]),
		numSections:       binary.LittleEndian.Uint16(pe[cof+2 : cof+4]),
		sizeOfOptionalHdr: binary.LittleEndian.Uint16(pe[cof+16 : cof+18]),
		characteristics:   binary.LittleEndian.Uint16(pe[cof+18 : cof+20]),
	}
	optOff := cof + 20
	if optOff+int(h.sizeOfOptionalHdr) > len(pe) {
		return nil, fmt.Errorf("%w: optional header past end of buffer", ErrBadPE)
	}
	h.optMagic = binary.LittleEndian.Uint16(pe[optOff : optOff+2])

	if h.machine != machineAMD64 || h.optMagic != pe32PlusMagic {
		return nil, fmt.Errorf("%w: machine=0x%x optMagic=0x%x", ErrUnsupportedArch, h.machine, h.optMagic)
	}
	if h.characteristics&dllCharacteristic != 0 {
		return nil, ErrNotEXE
	}

	// PE32+ optional header field offsets (relative to optOff):
	//   AddressOfEntryPoint @ +16  (uint32)
	//   ImageBase           @ +24  (uint64)
	//   SizeOfImage         @ +56  (uint32)
	//   SizeOfHeaders       @ +60  (uint32)
	//   DataDirectory[16]   @ +112 (each: uint32 RVA + uint32 Size)
	h.addressOfEntry = binary.LittleEndian.Uint32(pe[optOff+16 : optOff+20])
	h.imageBase = binary.LittleEndian.Uint64(pe[optOff+24 : optOff+32])
	h.sizeOfImage = binary.LittleEndian.Uint32(pe[optOff+56 : optOff+60])
	h.sizeOfHeaders = binary.LittleEndian.Uint32(pe[optOff+60 : optOff+64])

	dirsOff := optOff + 112
	for i := 0; i < numDataDirs; i++ {
		off := dirsOff + i*8
		if off+8 > len(pe) {
			return nil, fmt.Errorf("%w: data directory %d past end of buffer", ErrBadPE, i)
		}
		h.dataDirs[i] = dataDirectory{
			VirtualAddress: binary.LittleEndian.Uint32(pe[off : off+4]),
			Size:           binary.LittleEndian.Uint32(pe[off+4 : off+8]),
		}
	}

	if h.dataDirs[dirTLS].VirtualAddress != 0 {
		return nil, ErrTLSCallbacks
	}

	h.sectionTableOffset = optOff + int(h.sizeOfOptionalHdr)
	if h.sectionTableOffset+int(h.numSections)*40 > len(pe) {
		return nil, fmt.Errorf("%w: section table past end of buffer", ErrBadPE)
	}
	return h, nil
}

// readSection returns the i-th IMAGE_SECTION_HEADER from the
// section table. Bounds-checked by parseHeaders.
func readSection(pe []byte, h *peHeaders, i int) sectionEntry {
	off := h.sectionTableOffset + i*40
	var s sectionEntry
	copy(s.Name[:], pe[off:off+8])
	s.VirtualSize = binary.LittleEndian.Uint32(pe[off+8 : off+12])
	s.VirtualAddress = binary.LittleEndian.Uint32(pe[off+12 : off+16])
	s.SizeOfRawData = binary.LittleEndian.Uint32(pe[off+16 : off+20])
	s.PointerToRawData = binary.LittleEndian.Uint32(pe[off+20 : off+24])
	s.Characteristics = binary.LittleEndian.Uint32(pe[off+36 : off+40])
	return s
}
