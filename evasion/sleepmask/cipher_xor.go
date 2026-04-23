package sleepmask

// XORCipher is the classic repeating-key XOR. It has no cryptographic
// strength — a single known plaintext byte pair reveals a key byte —
// but for sleep masking that is not the threat model: the key lives
// only as long as the sleep, after which SecureZero wipes it. What
// matters is that a memory scanner cannot pattern-match the bytes
// while the region is under mask. XOR delivers that for zero CPU
// and zero external dependencies.
//
// This is Level 1 cryptography (see sleep-mask.md for the level
// taxonomy). For a slightly stronger cipher, use RC4 or AES-CTR; they
// cost more per cycle but resist known-plaintext attacks that a sharp
// analyst could pull off against a known shellcode prologue.
type XORCipher struct {
	// Size is the key length the cipher will request via KeySize.
	// Defaults to 32 bytes if left zero.
	Size int
}

// NewXORCipher returns an XORCipher with the default 32-byte key size.
func NewXORCipher() *XORCipher { return &XORCipher{Size: 32} }

// KeySize implements Cipher.
func (x *XORCipher) KeySize() int {
	if x == nil || x.Size <= 0 {
		return 32
	}
	return x.Size
}

// Apply implements Cipher.
func (x *XORCipher) Apply(buf, key []byte) {
	if len(buf) == 0 || len(key) == 0 {
		return
	}
	keyLen := len(key)
	for i := range buf {
		buf[i] ^= key[i%keyLen]
	}
}
