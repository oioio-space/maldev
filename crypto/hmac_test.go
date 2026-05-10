package crypto_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/oioio-space/maldev/crypto"
)

// TestHMACSHA256_RFC4231Vector pins the implementation against
// RFC 4231 Test Case 1:
//
//	Key  = 0x0b * 20
//	Data = "Hi There"
//	HMAC = b0344c61d8db38535ca8afceaf0bf12b
//	       881dc200c9833da726e9376c2e32cff7
func TestHMACSHA256_RFC4231Vector(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	data := []byte("Hi There")
	want, _ := hex.DecodeString(
		"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	got := crypto.HMACSHA256(key, data)
	if !bytes.Equal(got, want) {
		t.Errorf("RFC 4231 TC1 mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

// TestHMACSHA256_ReturnsThirtyTwoBytes — output is always 32 bytes
// regardless of input lengths.
func TestHMACSHA256_ReturnsThirtyTwoBytes(t *testing.T) {
	for _, ks := range []int{0, 1, 16, 32, 64, 256} {
		for _, ds := range []int{0, 1, 1024} {
			tag := crypto.HMACSHA256(make([]byte, ks), make([]byte, ds))
			if len(tag) != 32 {
				t.Errorf("len(HMACSHA256) = %d, want 32 (key=%d, data=%d)", len(tag), ks, ds)
			}
		}
	}
}

// TestVerifyHMACSHA256_AcceptsValidRejectsTampered exercises both
// branches of the constant-time compare.
func TestVerifyHMACSHA256_AcceptsValidRejectsTampered(t *testing.T) {
	key := []byte("operator-key")
	data := []byte("ciphertext-bytes")
	tag := crypto.HMACSHA256(key, data)

	if !crypto.VerifyHMACSHA256(key, data, tag) {
		t.Error("VerifyHMACSHA256 rejected its own tag")
	}
	// Flip a single bit in the tag.
	bad := append([]byte(nil), tag...)
	bad[0] ^= 0x01
	if crypto.VerifyHMACSHA256(key, data, bad) {
		t.Error("VerifyHMACSHA256 accepted tampered tag")
	}
	// Truncated tag.
	if crypto.VerifyHMACSHA256(key, data, tag[:31]) {
		t.Error("VerifyHMACSHA256 accepted truncated tag")
	}
	// Wrong key.
	if crypto.VerifyHMACSHA256([]byte("other-key"), data, tag) {
		t.Error("VerifyHMACSHA256 accepted tag under wrong key")
	}
	// Wrong data.
	if crypto.VerifyHMACSHA256(key, []byte("other-data"), tag) {
		t.Error("VerifyHMACSHA256 accepted tag for wrong data")
	}
}
