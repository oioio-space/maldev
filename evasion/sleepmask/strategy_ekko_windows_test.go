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

func TestEkkoStrategy_RejectsNonRC4Cipher(t *testing.T) {
	mask := New(Region{Addr: 0x1000, Size: 100}).
		WithStrategy(&EkkoStrategy{}).
		WithCipher(NewXORCipher())
	err := mask.Sleep(context.Background(), 10*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires *RC4Cipher")
}

func TestEkkoStrategy_RejectsMultiRegion(t *testing.T) {
	mask := New(
		Region{Addr: 0x1000, Size: 100},
		Region{Addr: 0x2000, Size: 100},
	).WithStrategy(&EkkoStrategy{}).WithCipher(NewRC4Cipher())
	err := mask.Sleep(context.Background(), 10*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one region")
}

func TestEkkoStrategy_CycleRoundTrip(t *testing.T) {
	t.Skip("EkkoStrategy ROP chain execution is WIP: RtlCaptureContext " +
		"requires 16-byte CONTEXT alignment, Rsp alignment on gadget entry, " +
		"and shadow-space separation from gadget args. Scaffold + input " +
		"validation ship in v0.12.0; chain execution is future work.")

	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42, 0x43, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&EkkoStrategy{}).
		WithCipher(NewRC4Cipher())
	require.NoError(t, mask.Sleep(context.Background(), 100*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored), "bytes must round-trip through EkkoStrategy")
}
