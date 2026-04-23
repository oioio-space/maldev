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

func TestSleepMask_EncryptDecrypt(t *testing.T) {
	data := []byte{0xCC, 0xCC, 0xCC, 0xCC, 0x90, 0x90, 0x90, 0x90}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))})
	require.NoError(t, mask.Sleep(context.Background(), 10*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored), "bytes must be restored after sleep")
}

func TestSleepMask_BusyTrig(t *testing.T) {
	data := []byte{0x41, 0x42, 0x43, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).
		WithStrategy(&InlineStrategy{UseBusyTrig: true})
	require.NoError(t, mask.Sleep(context.Background(), 10*time.Millisecond))

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

func TestSleepMask_EncryptedDuringSleep(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = 0xAA
	}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))})

	encrypted := make(chan bool, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		region := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
		allAA := true
		for _, b := range region {
			if b != 0xAA {
				allAA = false
				break
			}
		}
		encrypted <- !allAA
	}()

	require.NoError(t, mask.Sleep(context.Background(), 300*time.Millisecond))

	assert.True(t, <-encrypted, "bytes should be scrambled during sleep")
	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

func TestSleepMask_ZeroDuration(t *testing.T) {
	mask := New(Region{Addr: 0xDEAD, Size: 100})
	require.NoError(t, mask.Sleep(context.Background(), 0))
}

func TestSleepMask_NoRegions(t *testing.T) {
	mask := New()
	require.NoError(t, mask.Sleep(context.Background(), 10*time.Millisecond))
}

func TestSleepMask_CtxCancellation(t *testing.T) {
	data := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	mask := New(Region{Addr: addr, Size: uintptr(len(data))})
	err = mask.Sleep(ctx, 5*time.Second) // longer than ctx timeout
	require.Error(t, err, "Sleep must return ctx.Err when cancelled")
	require.ErrorIs(t, err, context.DeadlineExceeded)

	// Decrypt must have still run — bytes restored.
	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

func TestNew(t *testing.T) {
	t.Run("no_regions", func(t *testing.T) {
		m := New()
		require.NotNil(t, m)
	})
	t.Run("with_region", func(t *testing.T) {
		m := New(Region{Addr: 0x1000, Size: 64})
		require.NotNil(t, m)
	})
}

func TestMask_DefaultCipher(t *testing.T) {
	m := New()
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok, "default cipher must be *XORCipher")
}

func TestMask_DefaultStrategy(t *testing.T) {
	m := New()
	_, ok := m.strategy.(*InlineStrategy)
	assert.True(t, ok, "default strategy must be *InlineStrategy")
}

func TestMask_WithCipher_NilFallsBackToDefault(t *testing.T) {
	m := New().WithCipher(nil)
	_, ok := m.cipher.(*XORCipher)
	assert.True(t, ok)
}

func TestMask_WithStrategy_NilFallsBackToDefault(t *testing.T) {
	m := New().WithStrategy(nil)
	_, ok := m.strategy.(*InlineStrategy)
	assert.True(t, ok)
}
