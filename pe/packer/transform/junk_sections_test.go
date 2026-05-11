package transform_test

import (
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// peWithStub returns a synthetic PE buffer mirroring what the
// packer produces: 2 host sections + 1 stub appended at the end.
// Sized headers (SizeOfHeaders = 0x400) so the section table has
// real headroom for the inserts under test.
func peWithStub(t *testing.T) []byte {
	t.Helper()
	const (
		peOff         = 0x40
		coffOff       = peOff + 4
		sizeOfOptHdr  = 0xF0
		optOff        = coffOff + transform.PECOFFHdrSize
		secTableOff   = optOff + sizeOfOptHdr
		numSections   = 3
		sizeOfHeaders = 0x400
		sectionAlign  = 0x1000
		bufSize       = 0x1000
	)
	out := make([]byte, bufSize)
	out[0] = 'M'
	out[1] = 'Z'
	binary.LittleEndian.PutUint32(out[transform.PEELfanewOffset:], peOff)
	binary.LittleEndian.PutUint32(out[peOff:], 0x00004550) // "PE\0\0"
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFNumSectionsOffset:], numSections)
	binary.LittleEndian.PutUint16(out[coffOff+transform.COFFSizeOfOptHdrOffset:], sizeOfOptHdr)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSectionAlignOffset:], sectionAlign)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptFileAlignOffset:], 0x200)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfImageOffset:], 0x4000)
	binary.LittleEndian.PutUint32(out[optOff+transform.OptSizeOfHeadersOffset:], sizeOfHeaders)
	// Stamp section headers: .text @ 0x1000, .data @ 0x2000, stub @ 0x3000
	for i, name := range []string{".text", ".data", ".mldv"} {
		hdrOff := secTableOff + i*transform.PESectionHdrSize
		copy(out[hdrOff:], name)
		binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualSizeOffset:], 0x100)
		binary.LittleEndian.PutUint32(out[hdrOff+transform.SecVirtualAddressOffset:], uint32(0x1000+i*0x1000))
	}
	// OEP points at the stub (last section).
	binary.LittleEndian.PutUint32(out[optOff+transform.OptAddrEntryOffset:], 0x3000)
	return out
}

func readSection(t *testing.T, pe []byte, idx int) (name string, va, vs, char uint32) {
	t.Helper()
	const (
		peOff        = 0x40
		coffOff      = peOff + 4
		sizeOfOptHdr = 0xF0
		secTableOff  = coffOff + transform.PECOFFHdrSize + sizeOfOptHdr
	)
	hdrOff := secTableOff + idx*transform.PESectionHdrSize
	var nameBuf [8]byte
	copy(nameBuf[:], pe[hdrOff:hdrOff+8])
	for i, b := range nameBuf {
		if b == 0 {
			name = string(nameBuf[:i])
			break
		}
		if i == 7 {
			name = string(nameBuf[:])
		}
	}
	vs = binary.LittleEndian.Uint32(pe[hdrOff+transform.SecVirtualSizeOffset:])
	va = binary.LittleEndian.Uint32(pe[hdrOff+transform.SecVirtualAddressOffset:])
	char = binary.LittleEndian.Uint32(pe[hdrOff+transform.SecCharacteristicsOffset:])
	return
}

func readPENumSections(pe []byte) uint16 {
	const peOff = 0x40
	return binary.LittleEndian.Uint16(pe[peOff+4+transform.COFFNumSectionsOffset:])
}

func readPEOEP(pe []byte) uint32 {
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	return binary.LittleEndian.Uint32(pe[optOff+transform.OptAddrEntryOffset:])
}

func TestAppendJunkSeparators_ZeroCountIsNoop(t *testing.T) {
	pe := peWithStub(t)
	out, err := transform.AppendJunkSeparators(pe, 0, rand.New(rand.NewSource(1)))
	if err != nil {
		t.Fatalf("AppendJunkSeparators(0): %v", err)
	}
	if string(out) != string(pe) {
		t.Error("count=0 must return an unchanged copy of input")
	}
}

func TestAppendJunkSeparators_BumpsNumberOfSectionsOnly(t *testing.T) {
	pe := peWithStub(t)
	const count = 3
	const originalOEP = 0x3000
	out, err := transform.AppendJunkSeparators(pe, count, rand.New(rand.NewSource(42)))
	if err != nil {
		t.Fatalf("AppendJunkSeparators: %v", err)
	}
	if got := readPENumSections(out); got != 3+count {
		t.Errorf("NumberOfSections = %d, want %d", got, 3+count)
	}
	// OEP must be unchanged — separators go AFTER the stub VA-wise
	// so the stub keeps its original VA and RIP-relative addressing.
	if got := readPEOEP(out); got != originalOEP {
		t.Errorf("OEP = 0x%x, want 0x%x (stub must NOT move)", got, originalOEP)
	}
}

func TestAppendJunkSeparators_StubStaysInPlace(t *testing.T) {
	pe := peWithStub(t)
	const count = 2
	out, err := transform.AppendJunkSeparators(pe, count, rand.New(rand.NewSource(42)))
	if err != nil {
		t.Fatalf("AppendJunkSeparators: %v", err)
	}
	// Stub was at idx 2 with VA 0x3000 — must still be there.
	name, va, _, _ := readSection(t, out, 2)
	if name != ".mldv" {
		t.Errorf("section[2] name = %q, want .mldv (stub must NOT migrate)", name)
	}
	if va != 0x3000 {
		t.Errorf("stub VA = 0x%x, want 0x3000 (stub must NOT move)", va)
	}
}

func TestAppendJunkSeparators_SeparatorsHaveBssCharacteristics(t *testing.T) {
	pe := peWithStub(t)
	const count = 2
	out, err := transform.AppendJunkSeparators(pe, count, rand.New(rand.NewSource(42)))
	if err != nil {
		t.Fatalf("AppendJunkSeparators: %v", err)
	}
	want := transform.ScnCntUninitData | transform.ScnMemRead
	// Separators occupy table positions [3, 3+count-1] — after the stub.
	for i := 0; i < count; i++ {
		_, _, _, char := readSection(t, out, 3+i)
		if char != want {
			t.Errorf("separator %d Characteristics = 0x%x, want 0x%x", i, char, want)
		}
	}
}

func TestAppendJunkSeparators_SeparatorsPreserveAscendingVA(t *testing.T) {
	pe := peWithStub(t)
	const count = 3
	out, err := transform.AppendJunkSeparators(pe, count, rand.New(rand.NewSource(42)))
	if err != nil {
		t.Fatalf("AppendJunkSeparators: %v", err)
	}
	var lastVA uint32
	for i := 0; i < int(readPENumSections(out)); i++ {
		_, va, _, _ := readSection(t, out, i)
		if va < lastVA {
			t.Errorf("section[%d] VA 0x%x < previous 0x%x — table not sorted by VA", i, va, lastVA)
		}
		lastVA = va
	}
}

func TestAppendJunkSeparators_DeterministicGivenSeed(t *testing.T) {
	const count = 3
	a, _ := transform.AppendJunkSeparators(peWithStub(t), count, rand.New(rand.NewSource(777)))
	b, _ := transform.AppendJunkSeparators(peWithStub(t), count, rand.New(rand.NewSource(777)))
	if string(a) != string(b) {
		t.Error("same seed produced different output")
	}
}

func TestAppendJunkSeparators_RejectsHeaderOverflow(t *testing.T) {
	// SizeOfHeaders too small for even one extra header.
	pe := peWithStub(t)
	const optOff = 0x40 + 4 + transform.PECOFFHdrSize
	binary.LittleEndian.PutUint32(pe[optOff+transform.OptSizeOfHeadersOffset:], 0x80)
	_, err := transform.AppendJunkSeparators(pe, 5, rand.New(rand.NewSource(1)))
	if !errors.Is(err, transform.ErrSectionTableFull) {
		t.Errorf("got %v, want ErrSectionTableFull", err)
	}
}

func TestAppendJunkSeparators_DoesNotMutateInput(t *testing.T) {
	pe := peWithStub(t)
	pristine := make([]byte, len(pe))
	copy(pristine, pe)
	_, err := transform.AppendJunkSeparators(pe, 2, rand.New(rand.NewSource(1)))
	if err != nil {
		t.Fatalf("AppendJunkSeparators: %v", err)
	}
	if string(pe) != string(pristine) {
		t.Error("input slice was mutated")
	}
}
