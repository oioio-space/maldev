package sleepmask

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cipherCase table-drives the symmetric-Apply contract for every bundled
// cipher. Adding a new Cipher implementation only requires adding a row
// here — the contract tests run against all rows.
var cipherCases = []struct {
	name string
	newC func() Cipher
}{
	{"XOR/default", func() Cipher { return NewXORCipher() }},
	{"XOR/custom8", func() Cipher { return &XORCipher{Size: 8} }},
	{"RC4/default", func() Cipher { return NewRC4Cipher() }},
	{"AES-CTR", func() Cipher { return NewAESCTRCipher() }},
}

func TestCiphers_SymmetricRoundTrip(t *testing.T) {
	for _, tc := range cipherCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := tc.newC()
			plaintext := []byte{0xDE, 0xAD, 0xBE, 0xEF, 'M', 'A', 'L', 'D', 'E', 'V', 0xCC, 0x90, 0x00, 0xFF}
			buf := append([]byte(nil), plaintext...)
			key := make([]byte, c.KeySize())
			_, err := rand.Read(key)
			require.NoError(t, err)

			c.Apply(buf, key)
			assert.NotEqual(t, plaintext, buf, "after one Apply buf must differ from plaintext")

			c.Apply(buf, key)
			assert.Equal(t, plaintext, buf, "two Applys with the same key must restore plaintext")
		})
	}
}

func TestCiphers_EmptyBufIsNoOp(t *testing.T) {
	for _, tc := range cipherCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := tc.newC()
			key := make([]byte, c.KeySize())
			_, err := rand.Read(key)
			require.NoError(t, err)

			// nil and empty slice must both be accepted without panic.
			c.Apply(nil, key)
			c.Apply([]byte{}, key)
		})
	}
}

func TestCiphers_KeySizeNonZero(t *testing.T) {
	for _, tc := range cipherCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			c := tc.newC()
			assert.Greater(t, c.KeySize(), 0,
				"KeySize must be a positive byte count (got %d)", c.KeySize())
		})
	}
}

func TestXORCipher_NilReceiverStillWorks(t *testing.T) {
	var c *XORCipher
	assert.Equal(t, 32, c.KeySize(), "nil receiver falls back to default key size")
}

func TestXORCipher_ZeroSizeFallsBackToDefault(t *testing.T) {
	c := &XORCipher{Size: 0}
	assert.Equal(t, 32, c.KeySize())
}

func TestXORCipher_CustomKeySize(t *testing.T) {
	c := &XORCipher{Size: 7}
	assert.Equal(t, 7, c.KeySize())
	buf := bytes.Repeat([]byte{0xAA}, 20)
	key := []byte("0123456")
	c.Apply(buf, key)
	// Repeating-key XOR: byte i xor'd with key[i%7].
	expect := make([]byte, 20)
	for i := range expect {
		expect[i] = 0xAA ^ key[i%7]
	}
	assert.Equal(t, expect, buf)
}

func TestXORCipher_EmptyKeyIsNoOp(t *testing.T) {
	c := NewXORCipher()
	buf := []byte{0xDE, 0xAD}
	c.Apply(buf, nil)
	assert.Equal(t, []byte{0xDE, 0xAD}, buf)
	c.Apply(buf, []byte{})
	assert.Equal(t, []byte{0xDE, 0xAD}, buf)
}

func TestRC4Cipher_InvalidKeyPanics(t *testing.T) {
	c := NewRC4Cipher()
	assert.Panics(t, func() {
		c.Apply([]byte{0x00}, nil) // crypto/rc4 rejects zero-length keys
	})
}

func TestAESCTRCipher_InvalidKeyPanics(t *testing.T) {
	c := NewAESCTRCipher()
	assert.Panics(t, func() {
		c.Apply([]byte{0x00}, []byte("too-short"))
	})
}

func TestAESCTRCipher_KeySizeExact(t *testing.T) {
	c := NewAESCTRCipher()
	assert.Equal(t, 16+32, c.KeySize(), "AES-CTR expects 16 bytes IV + 32 bytes key")
}

func TestNewConstructors_ReturnNonNil(t *testing.T) {
	assert.NotNil(t, NewXORCipher())
	assert.NotNil(t, NewRC4Cipher())
	assert.NotNil(t, NewAESCTRCipher())
}

// Compile-time check that every bundled cipher satisfies Cipher.
var _ Cipher = (*XORCipher)(nil)
var _ Cipher = (*RC4Cipher)(nil)
var _ Cipher = (*AESCTRCipher)(nil)
