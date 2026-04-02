package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXORWithRepeatingKey(t *testing.T) {
	key := []byte("secret")
	data := []byte("hello world")
	encrypted, err := XORWithRepeatingKey(data, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encrypted, data) {
		t.Fatal("encrypted should differ from plaintext")
	}
	decrypted, err := XORWithRepeatingKey(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Fatalf("got %q, want %q", decrypted, data)
	}
}

func TestXOREmptyData(t *testing.T) {
	out, err := XORWithRepeatingKey([]byte{}, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatal("expected empty output")
	}
}

func TestXOREmptyKey(t *testing.T) {
	_, err := XORWithRepeatingKey([]byte("data"), []byte{})
	if err == nil {
		t.Fatal("expected error for empty key")
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

func TestChaCha20TamperedCiphertext(t *testing.T) {
	key, _ := NewChaCha20Key()
	ciphertext, _ := EncryptChaCha20(key, []byte("test"))
	ciphertext[len(ciphertext)-1] ^= 0xFF
	_, err := DecryptChaCha20(key, ciphertext)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext")
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

func TestAESGCMRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plaintext := []byte("AES-GCM round-trip test payload")
	ciphertext, err := EncryptAESGCM(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := DecryptAESGCM(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestAESGCMInvalidKeySize(t *testing.T) {
	shortKey := []byte("short")
	_, err := EncryptAESGCM(shortKey, []byte("data"))
	require.Error(t, err)

	_, err = DecryptAESGCM(shortKey, []byte("data"))
	require.Error(t, err)
}

func TestChaCha20RoundTrip(t *testing.T) {
	key, err := NewChaCha20Key()
	require.NoError(t, err)

	plaintext := []byte("ChaCha20 round-trip test payload")
	ciphertext, err := EncryptChaCha20(key, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)

	decrypted, err := DecryptChaCha20(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestChaCha20InvalidKey(t *testing.T) {
	shortKey := []byte("short")
	_, err := EncryptChaCha20(shortKey, []byte("data"))
	require.Error(t, err)
}

func TestRC4RoundTrip(t *testing.T) {
	key := []byte("rc4-roundtrip-key")
	data := []byte("RC4 is a symmetric stream cipher")

	// RC4 is its own inverse: applying twice returns original.
	once, err := EncryptRC4(key, data)
	require.NoError(t, err)
	assert.NotEqual(t, data, once, "single RC4 pass should differ from plaintext")

	twice, err := EncryptRC4(key, once)
	require.NoError(t, err)
	assert.Equal(t, data, twice)
}

func TestXORRoundTrip(t *testing.T) {
	key := []byte("xor-key")
	data := []byte("XOR round-trip test data")

	once, err := XORWithRepeatingKey(data, key)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(data, once), "XOR output should differ from input")

	twice, err := XORWithRepeatingKey(once, key)
	require.NoError(t, err)
	assert.Equal(t, data, twice)
}
