package crypto

import "fmt"

// ArithShift applies position-dependent arithmetic obfuscation:
//
//	out[i] = (in[i] + key[i%len(key)] + byte(i)) & 0xFF
//
// Unlike XOR, identical input bytes produce different output due to the
// position term, breaking simple frequency analysis.
// Not cryptographic — use as a signature-breaking layer only.
func ArithShift(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("arith: key must not be empty")
	}
	out := make([]byte, len(data))
	kl := len(key)
	for i, b := range data {
		out[i] = b + key[i%kl] + byte(i)
	}
	return out, nil
}

// ReverseArithShift reverses ArithShift.
func ReverseArithShift(data, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("arith: key must not be empty")
	}
	out := make([]byte, len(data))
	kl := len(key)
	for i, b := range data {
		out[i] = b - key[i%kl] - byte(i)
	}
	return out, nil
}
