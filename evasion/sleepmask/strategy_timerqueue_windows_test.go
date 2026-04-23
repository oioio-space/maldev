//go:build windows

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

func TestTimerQueueStrategy_CycleRoundTrip(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&TimerQueueStrategy{})
	require.NoError(t, mask.Sleep(context.Background(), 50*time.Millisecond))

	assert.Equal(t, data,
		[]byte(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))),
		"bytes must round-trip through TimerQueueStrategy")
}

func TestTimerQueueStrategy_CtxCancellation(t *testing.T) {
	data := []byte{0xAA, 0xBB}
	addr, _ := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&TimerQueueStrategy{})
	err := mask.Sleep(ctx, 5*time.Second)
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Region must be demasked after cancel (decrypt ran via DeleteTimerQueueTimer's blocking wait).
	assert.Equal(t, data, []byte(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))))
}
