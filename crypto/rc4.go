package crypto

import (
	"crypto/rc4"
	"fmt"
)

// EncryptRC4 encrypts/decrypts data with RC4 (symmetric).
// WARNING: RC4 is cryptographically broken. Use for compatibility only.
func EncryptRC4(key, data []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}
