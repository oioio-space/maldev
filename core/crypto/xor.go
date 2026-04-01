package crypto

// XORWithRepeatingKey encrypts/decrypts data with a repeating XOR key.
// Not cryptographically secure — use only for payload obfuscation.
func XORWithRepeatingKey(data, key []byte) []byte {
	out := make([]byte, len(data))
	kl := len(key)
	for i, b := range data {
		out[i] = b ^ key[i%kl]
	}
	return out
}
