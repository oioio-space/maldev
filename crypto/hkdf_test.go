package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/crypto"
)

// TestDeriveKeySalted_RFC5869Vector pins the implementation against
// RFC 5869 Appendix A.1 (Test Case 1, SHA-256). If this fails, the
// HKDF wiring has been broken and downstream subkeys diverge silently.
func TestDeriveKeySalted_RFC5869Vector(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c,
	}
	info := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9}
	want := []byte{
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
		0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
		0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
		0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
		0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
		0x58, 0x65,
	}
	got, err := crypto.DeriveKeySalted(ikm, salt, string(info), 42)
	if err != nil {
		t.Fatalf("DeriveKeySalted: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("RFC 5869 A.1 vector mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

// TestDeriveKey_DifferentLabelsDifferentKeys asserts the operational
// guarantee that two distinct labels produce statistically independent
// subkeys from the same secret. Catches "info parameter ignored"
// regressions.
func TestDeriveKey_DifferentLabelsDifferentKeys(t *testing.T) {
	secret := []byte("operator-master-secret-xyz")
	a, err := crypto.DeriveKey(secret, "stub-xor-key", 32)
	if err != nil {
		t.Fatalf("DeriveKey(a): %v", err)
	}
	b, err := crypto.DeriveKey(secret, "bundle-magic", 32)
	if err != nil {
		t.Fatalf("DeriveKey(b): %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("identical subkeys for different labels — info ignored?")
	}
	// Same call twice must be deterministic.
	a2, _ := crypto.DeriveKey(secret, "stub-xor-key", 32)
	if !bytes.Equal(a, a2) {
		t.Error("DeriveKey not deterministic for the same (secret,label,length)")
	}
}

// TestDeriveKey_LengthTooLarge pins the [crypto.ErrHKDFLengthTooLarge]
// sentinel — operators upstream of the underflow should be able to
// detect it explicitly.
func TestDeriveKey_LengthTooLarge(t *testing.T) {
	_, err := crypto.DeriveKey([]byte("k"), "label", 255*32+1)
	if !errors.Is(err, crypto.ErrHKDFLengthTooLarge) {
		t.Errorf("DeriveKey(L=8161) error = %v, want ErrHKDFLengthTooLarge", err)
	}
	// Negative length: same sentinel? — no, just any error. Pin
	// only that it doesn't silently succeed.
	if _, err := crypto.DeriveKey([]byte("k"), "label", -1); err == nil {
		t.Error("DeriveKey(L=-1) accepted negative length")
	}
}

// TestDeriveKey_ZeroLength returns an empty slice (not nil; HKDF
// "extract a 0-byte key" is a degenerate-but-legal case).
func TestDeriveKey_ZeroLength(t *testing.T) {
	out, err := crypto.DeriveKey([]byte("k"), "label", 0)
	if err != nil {
		t.Fatalf("DeriveKey(L=0): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("DeriveKey(L=0) length = %d, want 0", len(out))
	}
}
