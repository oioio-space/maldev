//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpawnWithSpoofedArgs_EmptyPath(t *testing.T) {
	pi, err := SpawnWithSpoofedArgs("", "fake", "real")
	assert.Nil(t, pi)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "executable path required")
}

func TestSpawnWithSpoofedArgs_EmptyPathNoArgs(t *testing.T) {
	pi, err := SpawnWithSpoofedArgs("", "", "")
	assert.Nil(t, pi)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "executable path required")
}

func TestUtf16LEBytes(t *testing.T) {
	b := utf16LEBytes("A")
	// "A" = 0x41,0x00 + null terminator 0x00,0x00
	assert.Equal(t, byte(0x41), b[0])
	assert.Equal(t, byte(0x00), b[1])
}
