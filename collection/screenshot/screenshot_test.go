//go:build windows

package screenshot

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCapture(t *testing.T) {
	data, err := Capture()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Verify PNG magic bytes: 0x89 P N G \r \n 0x1A \n
	pngHeader := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	assert.Equal(t, pngHeader, data[:8], "output should have PNG header")
}

func TestDisplayCount(t *testing.T) {
	n := DisplayCount()
	assert.GreaterOrEqual(t, n, 1, "at least one display expected")
}

func TestDisplayBounds(t *testing.T) {
	bounds := DisplayBounds(0)
	assert.Greater(t, bounds.Dx(), 0, "primary display width must be positive")
	assert.Greater(t, bounds.Dy(), 0, "primary display height must be positive")
}
