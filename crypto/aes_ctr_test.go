package crypto_test

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/crypto"
)

// TestAESCTR_Roundtrip exercises Encrypt → Decrypt across the three
// legal AES key sizes and a spread of plaintext lengths (including
// the cipher.NewCTR boundary at exactly aes.BlockSize == 16).
func TestAESCTR_Roundtrip(t *testing.T) {
	for _, ks := range []int{16, 24, 32} {
		key := bytes.Repeat([]byte{byte(ks)}, ks)
		for _, length := range []int{0, 1, 15, 16, 17, 31, 32, 1023, 65537} {
			pt := make([]byte, length)
			for i := range pt {
				pt[i] = byte(i * 7)
			}
			ct, err := crypto.EncryptAESCTR(key, pt)
			if err != nil {
				t.Fatalf("EncryptAESCTR(ks=%d, len=%d): %v", ks, length, err)
			}
			if got := len(ct); got != length+16 {
				t.Errorf("ct length = %d, want %d (16 IV + %d body)", got, length+16, length)
			}
			got, err := crypto.DecryptAESCTR(key, ct)
			if err != nil {
				t.Fatalf("DecryptAESCTR(ks=%d, len=%d): %v", ks, length, err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("roundtrip mismatch (ks=%d, len=%d)", ks, length)
			}
		}
	}
}

// TestAESCTR_RandomIV asserts two encryptions of the same plaintext
// with the same key produce different ciphertexts (different IV).
// Catches a 'forgot to call rand.Read' regression.
func TestAESCTR_RandomIV(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	pt := []byte("operator payload")
	a, err := crypto.EncryptAESCTR(key, pt)
	if err != nil {
		t.Fatalf("EncryptAESCTR: %v", err)
	}
	b, err := crypto.EncryptAESCTR(key, pt)
	if err != nil {
		t.Fatalf("EncryptAESCTR: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("identical ciphertext for two encryptions — IV not random")
	}
	// IV is the first 16 bytes; the body should still differ.
	if bytes.Equal(a[:16], b[:16]) {
		t.Error("identical IVs — rand.Read short-circuited?")
	}
}

// TestDecryptAESCTR_RejectsShort pins the contract that a ciphertext
// shorter than the IV (16 bytes) is rejected with an error rather
// than silently returning empty plaintext.
func TestDecryptAESCTR_RejectsShort(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, n := range []int{0, 1, 15} {
		if _, err := crypto.DecryptAESCTR(key, make([]byte, n)); err == nil {
			t.Errorf("DecryptAESCTR accepted len=%d (should reject)", n)
		}
	}
}

// TestEncryptAESCTR_RejectsBadKey checks the AES key-size validation
// (8, 17, 33 bytes — all illegal for AES).
func TestEncryptAESCTR_RejectsBadKey(t *testing.T) {
	pt := []byte("x")
	for _, ks := range []int{0, 1, 8, 17, 33, 64} {
		if _, err := crypto.EncryptAESCTR(make([]byte, ks), pt); err == nil {
			t.Errorf("EncryptAESCTR accepted key size %d (should reject)", ks)
		}
	}
}
