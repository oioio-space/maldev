package hash

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSsdeep(t *testing.T) {
	data := bytes.Repeat([]byte("Hello, World! "), 500)
	h, err := Ssdeep(data)
	require.NoError(t, err)
	assert.NotEmpty(t, h)
}

func TestSsdeepCompare_Similar(t *testing.T) {
	base := bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), 500)
	modified := make([]byte, len(base))
	copy(modified, base)
	modified[50] = 'Z'

	h1, _ := Ssdeep(base)
	h2, _ := Ssdeep(modified)

	score, err := SsdeepCompare(h1, h2)
	require.NoError(t, err)
	assert.Greater(t, score, 0, "similar data should have positive similarity")
}

func TestTLSH(t *testing.T) {
	data := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 50)
	h, err := TLSH(data)
	require.NoError(t, err)
	assert.NotEmpty(t, h)
}

func TestTLSHCompare(t *testing.T) {
	base := bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), 100)
	modified := make([]byte, len(base))
	copy(modified, base)
	modified[50] = 'Z'

	h1, _ := TLSH(base)
	h2, _ := TLSH(modified)

	dist, err := TLSHCompare(h1, h2)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, dist, 0)
}

func TestSsdeepFile(t *testing.T) {
	f, err := os.CreateTemp("", "ssdeep_test_*")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	data := bytes.Repeat([]byte("test data for ssdeep "), 200)
	_, err = f.Write(data)
	require.NoError(t, err)
	f.Close()

	h, err := SsdeepFile(f.Name())
	require.NoError(t, err)
	assert.NotEmpty(t, h)
}

func TestTLSHFile(t *testing.T) {
	f, err := os.CreateTemp("", "tlsh_test_*")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	data := bytes.Repeat([]byte("test data for tlsh hashing "), 100)
	_, err = f.Write(data)
	require.NoError(t, err)
	f.Close()

	h, err := TLSHFile(f.Name())
	require.NoError(t, err)
	assert.NotEmpty(t, h)
}
