package crypto_test

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/crypto"
)

// TestChaCha20Raw_Roundtrip exercises Encrypt → Decrypt across a
// spread of plaintext lengths.
func TestChaCha20Raw_Roundtrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, length := range []int{0, 1, 63, 64, 65, 1023, 65537} {
		pt := make([]byte, length)
		for i := range pt {
			pt[i] = byte(i * 13)
		}
		ct, err := crypto.EncryptChaCha20Raw(key, pt)
		if err != nil {
			t.Fatalf("EncryptChaCha20Raw(len=%d): %v", length, err)
		}
		if got := len(ct); got != length+24 {
			t.Errorf("ct length = %d, want %d (24 nonce + %d body)", got, length+24, length)
		}
		got, err := crypto.DecryptChaCha20Raw(key, ct)
		if err != nil {
			t.Fatalf("DecryptChaCha20Raw(len=%d): %v", length, err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("roundtrip mismatch (len=%d)", length)
		}
	}
}

// TestChaCha20Raw_RandomNonce — same plaintext + key → different
// ciphertexts across two encryptions. Catches 'forgot rand.Read'.
func TestChaCha20Raw_RandomNonce(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	pt := []byte("hello")
	a, _ := crypto.EncryptChaCha20Raw(key, pt)
	b, _ := crypto.EncryptChaCha20Raw(key, pt)
	if bytes.Equal(a, b) {
		t.Error("identical ciphertexts — nonce not random")
	}
}

// TestChaCha20Raw_RejectsBadKey checks the strict 32-byte key check.
func TestChaCha20Raw_RejectsBadKey(t *testing.T) {
	for _, ks := range []int{0, 1, 16, 24, 31, 33, 64} {
		if _, err := crypto.EncryptChaCha20Raw(make([]byte, ks), []byte("x")); err == nil {
			t.Errorf("EncryptChaCha20Raw accepted key size %d", ks)
		}
		if _, err := crypto.DecryptChaCha20Raw(make([]byte, ks), make([]byte, 32)); err == nil {
			t.Errorf("DecryptChaCha20Raw accepted key size %d", ks)
		}
	}
}

// TestDecryptChaCha20Raw_RejectsShort — ciphertext < nonce errors.
func TestDecryptChaCha20Raw_RejectsShort(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	for _, n := range []int{0, 1, 23} {
		if _, err := crypto.DecryptChaCha20Raw(key, make([]byte, n)); err == nil {
			t.Errorf("DecryptChaCha20Raw accepted len=%d", n)
		}
	}
}
