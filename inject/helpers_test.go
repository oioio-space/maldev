package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateShellcode_Empty(t *testing.T) {
	err := validateShellcode([]byte{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateShellcode_Nil(t *testing.T) {
	err := validateShellcode(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestValidateShellcode_Valid(t *testing.T) {
	err := validateShellcode([]byte{0x90, 0xCC})
	assert.NoError(t, err)
}

func TestXorEncodeShellcode(t *testing.T) {
	original := []byte{0x41, 0x42, 0x43, 0x44, 0x45}
	encoded, key, err := xorEncodeShellcode(original)
	require.NoError(t, err)

	assert.Len(t, encoded, len(original))
	// Encoded bytes should differ from original (key=0 is possible but
	// extremely unlikely with crypto/rand).
	assert.NotEqual(t, original, encoded, "encoded shellcode should differ from original")
	_ = key // key is used in the round-trip test below
}

func TestXorEncodeShellcode_RoundTrip(t *testing.T) {
	original := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}
	encoded, key, err := xorEncodeShellcode(original)
	require.NoError(t, err)

	// Manually XOR the encoded bytes with the key to recover the original.
	decoded := make([]byte, len(encoded))
	for i, b := range encoded {
		decoded[i] = b ^ key
	}
	assert.Equal(t, original, decoded, "XOR round-trip should recover original shellcode")
}

func TestCpuDelay(t *testing.T) {
	// cpuDelay uses default config (5M iterations) which is slow.
	// Call cpuDelayN directly with small values to keep the test fast.
	require.NotPanics(t, func() {
		cpuDelayN(100, 50)
	})
}
