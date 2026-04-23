package sleepmask

import (
	"crypto/aes"
	"crypto/cipher"
)

// AESCTRCipher wraps AES-256 in CTR mode. The 32-byte key is split:
// the first aes.BlockSize (16) bytes are used as the IV for the CTR
// stream; the next 32 bytes are the AES-256 key. The caller-facing
// KeySize is therefore 48 bytes (16 IV + 32 key) — larger than XOR or
// RC4 but negligible vs the sleep duration.
//
// CTR keeps the same symmetric-Apply contract as the other ciphers
// (encrypt twice to round-trip) because CTR xor-masking is
// self-inverse. Each Apply call re-seeds the stream from the IV, so
// the Cipher instance holds no state.
//
// This is Level 3 in the sleep-mask cipher taxonomy — expensive
// enough that you only reach for it when the scanner is doing real
// entropy analysis on RW regions (some products flag high-entropy RW
// allocations even without matching signatures; AES bytes pegged at
// max entropy are arguably more suspicious than XOR-scrambled bytes
// that retain some statistical structure of the plaintext).
type AESCTRCipher struct{}

// NewAESCTRCipher returns a ready-to-use AES-256-CTR cipher.
func NewAESCTRCipher() *AESCTRCipher { return &AESCTRCipher{} }

// KeySize implements Cipher. 16 bytes IV + 32 bytes AES key = 48.
func (*AESCTRCipher) KeySize() int { return aes.BlockSize + 32 }

// Apply implements Cipher. Panics on bad key lengths.
func (*AESCTRCipher) Apply(buf, key []byte) {
	if len(buf) == 0 {
		return
	}
	const wantLen = aes.BlockSize + 32
	if len(key) != wantLen {
		panic("sleepmask/aes: key must be exactly 48 bytes (16 IV + 32 AES key)")
	}
	iv := key[:aes.BlockSize]
	aesKey := key[aes.BlockSize : aes.BlockSize+32]
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		panic("sleepmask/aes: " + err.Error())
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(buf, buf)
}
