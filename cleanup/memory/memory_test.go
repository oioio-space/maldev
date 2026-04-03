//go:build windows

package memory

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestSecureZero(t *testing.T) {
	buf := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42}
	SecureZero(buf)
	for i, b := range buf {
		assert.Equal(t, byte(0), b, "byte at index %d should be zero", i)
	}
}

func TestSecureZero_Empty(t *testing.T) {
	// Should not panic on empty slice.
	SecureZero(nil)
	SecureZero([]byte{})
}

func TestWipeAndFree(t *testing.T) {
	size := uintptr(4096)
	addr, err := windows.VirtualAlloc(0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	require.NoError(t, err)

	// Write recognizable pattern.
	region := unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(size))
	for i := range region {
		region[i] = 0xAA
	}

	err = WipeAndFree(addr, size)
	require.NoError(t, err)

	// After VirtualFree the pages are released. We cannot read them
	// without access violation, so success of WipeAndFree is sufficient.
}

func TestWipeAndFree_ZeroAddr(t *testing.T) {
	err := WipeAndFree(0, 4096)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero")
}

func TestWipeAndFree_ZeroSize(t *testing.T) {
	err := WipeAndFree(0xDEAD, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero")
}
