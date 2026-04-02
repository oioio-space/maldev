//go:build windows

package api

import (
	"errors"
	"testing"
	"unsafe"

	"github.com/oioio-space/maldev/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestPatchMemory(t *testing.T) {
	testutil.RequireIntrusive(t)

	const size = 64
	addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	require.NoError(t, err, "VirtualAlloc failed")
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE) //nolint:errcheck

	// Write initial marker bytes.
	initial := []byte{0xAA, 0xBB, 0xCC}
	for i, b := range initial {
		*(*byte)(unsafe.Pointer(addr + uintptr(i))) = b
	}

	patch := []byte{0x11, 0x22, 0x33}
	err = PatchMemory(addr, patch)
	require.NoError(t, err, "PatchMemory failed")

	for i, want := range patch {
		got := *(*byte)(unsafe.Pointer(addr + uintptr(i)))
		assert.Equalf(t, want, got, "byte at offset %d: want 0x%02X, got 0x%02X", i, want, got)
	}
}

func TestErrProcNotFound(t *testing.T) {
	proc := windows.NewLazySystemDLL("nonexistent_12345.dll").NewProc("Fake")
	err := PatchProc(proc, []byte{0x90})
	assert.True(t, errors.Is(err, ErrProcNotFound), "expected ErrProcNotFound, got: %v", err)
}
