//go:build windows

package lsassdump

import (
	"errors"
	"testing"

	"github.com/oioio-space/maldev/kernel/driver"
)

// pplMockRW backs ReadKernel + WriteKernel with a single contiguous
// region keyed by base — enough for Unprotect/Reprotect tests that
// only touch the EPROCESS+ProtectionOffset byte.
type pplMockRW struct {
	regions map[uintptr][]byte
}

func newPPLMockRW(regions map[uintptr][]byte) *pplMockRW {
	return &pplMockRW{regions: regions}
}

func (m *pplMockRW) ReadKernel(addr uintptr, buf []byte) (int, error) {
	for base, region := range m.regions {
		if addr >= base && addr+uintptr(len(buf)) <= base+uintptr(len(region)) {
			off := addr - base
			n := copy(buf, region[off:])
			return n, nil
		}
	}
	return 0, errors.New("ppl mock: region miss on read")
}

func (m *pplMockRW) WriteKernel(addr uintptr, data []byte) (int, error) {
	for base, region := range m.regions {
		if addr >= base && addr+uintptr(len(data)) <= base+uintptr(len(region)) {
			off := addr - base
			n := copy(region[off:], data)
			return n, nil
		}
	}
	return 0, errors.New("ppl mock: region miss on write")
}

// TestPPLToken_IsZeroOnDefault keeps the deferred-cleanup idiom honest.
func TestPPLToken_IsZeroOnDefault(t *testing.T) {
	var tok PPLToken
	if !tok.IsZero() {
		t.Error("zero PPLToken.IsZero() = false, want true")
	}
}

// TestUnprotect_NilReadWriterReturnsErrNotLoaded checks the nil-rw
// guard.
func TestUnprotect_NilReadWriterReturnsErrNotLoaded(t *testing.T) {
	tab := PPLOffsetTable{Build: 19045, ProtectionOffset: 0x87A}
	_, err := Unprotect(nil, 0xFFFF000000001000, tab)
	if !errors.Is(err, driver.ErrNotLoaded) {
		t.Errorf("Unprotect(nil, …) err = %v, want driver.ErrNotLoaded", err)
	}
}

// TestUnprotect_ZeroEProcess refuses to write at 0.
func TestUnprotect_ZeroEProcess(t *testing.T) {
	rw := newPPLMockRW(nil)
	tab := PPLOffsetTable{Build: 19045, ProtectionOffset: 0x87A}
	_, err := Unprotect(rw, 0, tab)
	if !errors.Is(err, ErrInvalidEProcess) {
		t.Errorf("Unprotect(_, 0, _) err = %v, want ErrInvalidEProcess", err)
	}
}

// TestUnprotect_ZeroProtectionOffset rejects the unfilled-table
// foot-gun.
func TestUnprotect_ZeroProtectionOffset(t *testing.T) {
	rw := newPPLMockRW(nil)
	_, err := Unprotect(rw, 0xFFFF000000001000, PPLOffsetTable{})
	if !errors.Is(err, ErrInvalidProtectionOffset) {
		t.Errorf("Unprotect(_, _, zero tab) err = %v, want ErrInvalidProtectionOffset", err)
	}
}

// TestUnprotect_ZerosProtectionAndCapturesOriginal is the happy path:
// Unprotect zeros the byte and the returned token carries the original.
func TestUnprotect_ZerosProtectionAndCapturesOriginal(t *testing.T) {
	const eprocess uintptr = 0xFFFFC0010A1B2C00
	const offset uint32 = 0x87A
	const original byte = 0x61 // PS_PROTECTED_SIGNER_LSASS-LIGHT-WINDOWS

	region := make([]byte, offset+1)
	region[offset] = original
	rw := newPPLMockRW(map[uintptr][]byte{eprocess: region})
	tab := PPLOffsetTable{Build: 19045, ProtectionOffset: offset}

	tok, err := Unprotect(rw, eprocess, tab)
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if tok.OriginalProtection != original {
		t.Errorf("token.OriginalProtection = 0x%X, want 0x%X", tok.OriginalProtection, original)
	}
	if tok.EProcess != eprocess || tok.ProtectionOffset != offset {
		t.Errorf("token EPROCESS/offset = 0x%X/0x%X, want 0x%X/0x%X",
			tok.EProcess, tok.ProtectionOffset, eprocess, offset)
	}
	if region[offset] != 0 {
		t.Errorf("PS_PROTECTION post-Unprotect = 0x%X, want 0", region[offset])
	}
}

// TestReprotect_RoundTrips Unprotect → Reprotect must leave the byte
// exactly as found.
func TestReprotect_RoundTrips(t *testing.T) {
	const eprocess uintptr = 0xFFFFC0010A1B2C00
	const offset uint32 = 0x87A
	const original byte = 0x41

	region := make([]byte, offset+1)
	region[offset] = original
	rw := newPPLMockRW(map[uintptr][]byte{eprocess: region})
	tab := PPLOffsetTable{Build: 19045, ProtectionOffset: offset}

	tok, err := Unprotect(rw, eprocess, tab)
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}
	if err := Reprotect(tok, rw); err != nil {
		t.Fatalf("Reprotect: %v", err)
	}
	if region[offset] != original {
		t.Errorf("PS_PROTECTION post-Reprotect = 0x%X, want 0x%X", region[offset], original)
	}
}

// TestReprotect_ZeroTokenIsNoOp covers the deferred-cleanup idiom.
func TestReprotect_ZeroTokenIsNoOp(t *testing.T) {
	if err := Reprotect(PPLToken{}, newPPLMockRW(nil)); err != nil {
		t.Errorf("Reprotect(zero token) = %v, want nil", err)
	}
}

// TestReprotect_NilReadWriterReturnsErrNotLoaded mirrors Unprotect's
// nil-rw guard for non-zero tokens.
func TestReprotect_NilReadWriterReturnsErrNotLoaded(t *testing.T) {
	tok := PPLToken{EProcess: 0x1000, OriginalProtection: 0x41, ProtectionOffset: 0x87A}
	if err := Reprotect(tok, nil); !errors.Is(err, driver.ErrNotLoaded) {
		t.Errorf("Reprotect(_, nil) err = %v, want driver.ErrNotLoaded", err)
	}
}
