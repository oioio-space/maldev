package sleepmask

import "crypto/rc4"

// RC4Cipher wraps the stdlib crypto/rc4 stream cipher. Each Apply call
// re-creates the cipher state from the key, so calling Apply twice
// (encrypt then decrypt) round-trips even though RC4 itself is stateful
// — the state is per-call, not per-Cipher-instance. This matches the
// "symmetric, stateless Cipher" contract the mask relies on.
//
// This is Level 2 cryptography in the sleep-mask taxonomy — the same
// algorithm Windows' SystemFunction032 exposes (which Ekko famously
// calls from a ROP chain). Cryptographic RC4 is deprecated for general
// use, but for per-sleep keys it gives a meaningful step up from XOR
// against known-plaintext analysis without bringing in AES round keys.
type RC4Cipher struct {
	// Size is the key length in bytes. Valid: 1..256. Defaults to 16.
	Size int
}

// NewRC4Cipher returns an RC4Cipher with the default 16-byte key size.
func NewRC4Cipher() *RC4Cipher { return &RC4Cipher{Size: 16} }

// KeySize implements Cipher.
func (c *RC4Cipher) KeySize() int {
	if c == nil || c.Size <= 0 {
		return 16
	}
	return c.Size
}

// Apply implements Cipher. Panics if key length is not in 1..256 —
// that's crypto/rc4.NewCipher's own contract; we surface it rather
// than hiding silent corruption.
func (c *RC4Cipher) Apply(buf, key []byte) {
	if len(buf) == 0 {
		return
	}
	rc, err := rc4.NewCipher(key)
	if err != nil {
		// rc4.NewCipher only errors on invalid key sizes.
		panic("sleepmask/rc4: " + err.Error())
	}
	rc.XORKeyStream(buf, buf)
}
