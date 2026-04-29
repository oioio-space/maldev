package cert

import (
	"encoding/binary"
	"testing"
)

// minimalPE returns a 320-byte buffer shaped like a PE32 image: DOS
// stub with e_lfanew = 0x40, "PE\0\0" signature, FileHeader, and a
// 240-byte optional header. Enough for the checksum routines to
// resolve their offset without needing a real on-disk fixture.
func minimalPE() []byte {
	const (
		lfanew  = 0x40
		fhSize  = 20
		ohSize  = 240 // PE32 optional header
		total   = lfanew + 4 + fhSize + ohSize
	)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0x3C:], lfanew)
	copy(buf[lfanew:], []byte{'P', 'E', 0, 0})
	// Sprinkle a few non-zero bytes so the checksum is not trivially zero.
	for i := lfanew + 4 + fhSize; i < total; i += 7 {
		buf[i] = byte(i & 0xFF)
	}
	return buf
}

func TestPatchPECheckSum_RejectsInvalid(t *testing.T) {
	if err := PatchPECheckSum([]byte{0, 1, 2}); err != ErrInvalidPE {
		t.Errorf("err on short input = %v, want ErrInvalidPE", err)
	}
}

func TestPatchPECheckSum_IsIdempotent(t *testing.T) {
	pe := minimalPE()
	if err := PatchPECheckSum(pe); err != nil {
		t.Fatalf("first patch: %v", err)
	}
	off, err := peChecksumOffset(pe)
	if err != nil {
		t.Fatalf("offset: %v", err)
	}
	first := binary.LittleEndian.Uint32(pe[off : off+4])
	if first == 0 {
		t.Fatal("first checksum is zero on a non-zero PE")
	}

	if err := PatchPECheckSum(pe); err != nil {
		t.Fatalf("second patch: %v", err)
	}
	second := binary.LittleEndian.Uint32(pe[off : off+4])
	if first != second {
		t.Errorf("checksum drift: first=0x%08x second=0x%08x", first, second)
	}
}

func TestPatchPECheckSum_VerificationProperty(t *testing.T) {
	// MS verification: zero out CheckSum, recompute, expect equality
	// with the value already stored.
	pe := minimalPE()
	if err := PatchPECheckSum(pe); err != nil {
		t.Fatalf("patch: %v", err)
	}
	off, _ := peChecksumOffset(pe)
	stored := binary.LittleEndian.Uint32(pe[off : off+4])

	binary.LittleEndian.PutUint32(pe[off:off+4], 0)
	recomputed := computePECheckSum(pe, off)
	if recomputed != stored {
		t.Errorf("verification mismatch: stored=0x%08x recomputed=0x%08x", stored, recomputed)
	}
}
