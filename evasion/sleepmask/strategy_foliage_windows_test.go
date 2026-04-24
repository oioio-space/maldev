//go:build windows && amd64

package sleepmask

import (
	"context"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestFoliageStrategy_RejectsNonRC4Cipher(t *testing.T) {
	mask := New(Region{Addr: 0x1000, Size: 100}).
		WithStrategy(&FoliageStrategy{}).
		WithCipher(NewXORCipher())
	err := mask.Sleep(context.Background(), 10*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires *RC4Cipher")
}

func TestFoliageStrategy_RejectsMultiRegion(t *testing.T) {
	mask := New(
		Region{Addr: 0x1000, Size: 100},
		Region{Addr: 0x2000, Size: 100},
	).WithStrategy(&FoliageStrategy{}).WithCipher(NewRC4Cipher())
	err := mask.Sleep(context.Background(), 10*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one region")
}

func TestFoliageStrategy_CycleRoundTrip(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42, 0x43, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&FoliageStrategy{}).
		WithCipher(NewRC4Cipher())
	require.NoError(t, mask.Sleep(context.Background(), 100*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored), "bytes must round-trip through FoliageStrategy")
}

// TestFoliageStrategy_CustomScrubBytes checks that user-provided
// ScrubBytes values are honored (below the safe cap) and that
// over-requesting gets silently clamped rather than crashing — the
// safe max is exactly `foliageMaxSafeScrub`; a larger value would
// zero the gadget-2 memset's own saved rdi + return address.
func TestFoliageStrategy_CustomScrubBytes(t *testing.T) {
	data := []byte{0xFE, 0xED, 0xFA, 0xCE}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	// One shadow frame = half the default. Explicitly sub-max.
	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&FoliageStrategy{ScrubBytes: ekkoShadowStride}).
		WithCipher(NewRC4Cipher())
	require.NoError(t, mask.Sleep(context.Background(), 50*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

// TestFoliageStrategy_OverMaxScrubClamped verifies that requesting a
// scrub range beyond the safe maximum is silently clamped and the
// cycle still completes cleanly.
func TestFoliageStrategy_OverMaxScrubClamped(t *testing.T) {
	data := []byte{0x11, 0x22, 0x33, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&FoliageStrategy{ScrubBytes: 0xFFFFFF}). // way over the cap
		WithCipher(NewRC4Cipher())
	require.NoError(t, mask.Sleep(context.Background(), 50*time.Millisecond))
	assert.Equal(t, data, []byte(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))))
}
