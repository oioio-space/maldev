package runtime_test

import (
	"encoding/binary"
	"testing"
)

// dirEntry mirrors the on-wire IMAGE_DATA_DIRECTORY (8 bytes:
// VirtualAddress + Size) used in the optional header.
type dirEntry struct {
	VirtualAddress uint32
	Size           uint32
}

// headerOpts shape what buildHeaderOnlyPE emits. Only fields
// the parse-rejection tests need are wired today; extend
// per-test as new test cases land.
type headerOpts struct {
	Machine         uint16 // COFF File Header Machine
	OptMagic        uint16 // Optional Header Magic (0x10B = PE32, 0x20B = PE32+)
	Characteristics uint16 // COFF File Header Characteristics (0x2000 = DLL)
	TLSDir          dirEntry
}

// buildHeaderOnlyPE writes a minimal-but-valid-enough PE that
// the loader's parseHeaders walk reaches the rejection check
// matching the test scenario. The body after the headers is
// zeroed; no sections are emitted because the rejection paths
// always trip before the section-table walk.
func buildHeaderOnlyPE(t *testing.T, o headerOpts) []byte {
	t.Helper()
	const peOff = 0x40
	const optHdrSize = 240 // PE32+ Optional Header
	const headersSize = peOff + 4 + 20 + optHdrSize

	pe := make([]byte, headersSize)

	// DOS header: just the magic and e_lfanew at offset 60.
	pe[0] = 'M'
	pe[1] = 'Z'
	binary.LittleEndian.PutUint32(pe[60:64], peOff)

	// PE signature.
	binary.LittleEndian.PutUint32(pe[peOff:peOff+4], 0x00004550)

	// COFF File Header (20 bytes starting at peOff+4).
	cof := peOff + 4
	binary.LittleEndian.PutUint16(pe[cof:cof+2], o.Machine)
	binary.LittleEndian.PutUint16(pe[cof+2:cof+4], 0) // NumberOfSections
	// SizeOfOptionalHeader = optHdrSize:
	binary.LittleEndian.PutUint16(pe[cof+16:cof+18], optHdrSize)
	binary.LittleEndian.PutUint16(pe[cof+18:cof+20], o.Characteristics)

	// Optional Header.
	opt := cof + 20
	binary.LittleEndian.PutUint16(pe[opt:opt+2], o.OptMagic)

	// Data directories live at opt+112 in PE32+. Each entry is 8
	// bytes (VA + Size). TLS is index 9 → off = opt + 112 + 9*8.
	if o.OptMagic == 0x20B {
		tlsOff := opt + 112 + 9*8
		binary.LittleEndian.PutUint32(pe[tlsOff:tlsOff+4], o.TLSDir.VirtualAddress)
		binary.LittleEndian.PutUint32(pe[tlsOff+4:tlsOff+8], o.TLSDir.Size)
	}

	return pe
}
