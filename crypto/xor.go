package crypto

import "fmt"

// XORWithRepeatingKey encrypts/decrypts data with a repeating XOR key.
// Not cryptographically secure — use only for payload obfuscation.
func XORWithRepeatingKey(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key must not be empty")
	}
	out := make([]byte, len(data))
	kl := len(key)
	for i, b := range data {
		out[i] = b ^ key[i%kl]
	}
	return out, nil
}
