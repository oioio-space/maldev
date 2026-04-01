package crypto

import (
	"bytes"
	"testing"
)

func TestXORWithRepeatingKey(t *testing.T) {
	key := []byte("secret")
	data := []byte("hello world")
	encrypted := XORWithRepeatingKey(data, key)
	if bytes.Equal(encrypted, data) {
		t.Fatal("encrypted should differ from plaintext")
	}
	decrypted := XORWithRepeatingKey(encrypted, key)
	if !bytes.Equal(decrypted, data) {
		t.Fatalf("got %q, want %q", decrypted, data)
	}
}

func TestXOREmptyData(t *testing.T) {
	// XOR with empty data should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panicked: %v", r)
		}
	}()
	out := XORWithRepeatingKey([]byte{}, []byte("key"))
	if len(out) != 0 {
		t.Fatal("expected empty output")
	}
}

func TestAESGCMRoundtrip(t *testing.T) {
	key, err := NewAESKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
	plaintext := []byte("this is a secret message for testing AES-GCM")
	ciphertext, err := EncryptAESGCM(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Fatal("ciphertext should differ from plaintext")
	}
	decrypted, err := DecryptAESGCM(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("got %q, want %q", decrypted, plaintext)
	}
}

func TestAESGCMBadKey(t *testing.T) {
	_, err := EncryptAESGCM([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
	_, err = DecryptAESGCM([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestAESGCMTampered(t *testing.T) {
	key, _ := NewAESKey()
	ciphertext, _ := EncryptAESGCM(key, []byte("test"))
	// Tamper with ciphertext
	ciphertext[len(ciphertext)-1] ^= 0xFF
	_, err := DecryptAESGCM(key, ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestAESGCMDifferentCiphertextEachTime(t *testing.T) {
	key, _ := NewAESKey()
	plaintext := []byte("same plaintext")
	ct1, _ := EncryptAESGCM(key, plaintext)
	ct2, _ := EncryptAESGCM(key, plaintext)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions of same plaintext should produce different ciphertext (random nonce)")
	}
}

func TestChaCha20Roundtrip(t *testing.T) {
	key, err := NewChaCha20Key()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("chacha20 test message with some length")
	ciphertext, err := EncryptChaCha20(key, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptChaCha20(key, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("got %q, want %q", decrypted, plaintext)
	}
}

func TestChaCha20BadKey(t *testing.T) {
	_, err := EncryptChaCha20([]byte("short"), []byte("data"))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestChaCha20TamperedCiphertext(t *testing.T) {
	key, _ := NewChaCha20Key()
	ciphertext, _ := EncryptChaCha20(key, []byte("test"))
	ciphertext[len(ciphertext)-1] ^= 0xFF
	_, err := DecryptChaCha20(key, ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
}

func TestRC4Roundtrip(t *testing.T) {
	key := []byte("rc4testkey")
	data := []byte("hello rc4")
	encrypted, err := EncryptRC4(key, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := EncryptRC4(key, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatalf("got %q, want %q", decrypted, data)
	}
}

func TestRC4EmptyKey(t *testing.T) {
	_, err := EncryptRC4([]byte{}, []byte("data"))
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestRC4EmptyData(t *testing.T) {
	out, err := EncryptRC4([]byte("key"), []byte{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatal("expected empty output for empty data")
	}
}
