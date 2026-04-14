//go:build windows

package sleepmask

import (
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestSleepMask_EncryptDecrypt(t *testing.T) {
	// Allocate RWX memory with known content.
	data := []byte{0xCC, 0xCC, 0xCC, 0xCC, 0x90, 0x90, 0x90, 0x90}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	// Copy test data.
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))})

	// Sleep for a very short time — just test the encrypt/decrypt cycle.
	mask.Sleep(10 * time.Millisecond)

	// After sleep, data should be restored to original.
	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored), "data should be restored after encrypted sleep")
}

func TestSleepMask_BusyTrig(t *testing.T) {
	data := []byte{0x41, 0x42, 0x43, 0x44}
	addr, err := windows.VirtualAlloc(0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)

	mask := New(Region{Addr: addr, Size: uintptr(len(data))}).WithMethod(MethodBusyTrig)
	mask.Sleep(10 * time.Millisecond)

	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored))
}

// TestSleepMask_EncryptedDuringSleep verifies memory is actually encrypted
// while sleeping, not just restored after. A goroutine checks bytes mid-sleep.
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
		// Wait for encryption to happen, then check bytes.
		time.Sleep(50 * time.Millisecond)
		region := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
		allAA := true
		for _, b := range region {
			if b != 0xAA {
				allAA = false
				break
			}
		}
		encrypted <- !allAA // true if at least one byte changed
	}()

	mask.Sleep(300 * time.Millisecond)

	wasEncrypted := <-encrypted
	assert.True(t, wasEncrypted, "memory should be XOR-encrypted during sleep (all bytes were still 0xAA)")

	// Verify restored after sleep.
	restored := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data))
	assert.Equal(t, data, []byte(restored), "data must be restored after sleep")
}

func TestSleepMask_ZeroDuration(t *testing.T) {
	// Should not panic or modify anything.
	mask := New(Region{Addr: 0xDEAD, Size: 100})
	mask.Sleep(0) // no-op
}

func TestSleepMask_NoRegions(t *testing.T) {
	mask := New()
	mask.Sleep(10 * time.Millisecond) // no-op, no panic
}

func TestNew(t *testing.T) {
	// Verify New returns a non-nil *Mask with and without regions.
	t.Run("no_regions", func(t *testing.T) {
		m := New()
		require.NotNil(t, m, "New() without regions must return non-nil *Mask")
	})

	t.Run("with_region", func(t *testing.T) {
		m := New(Region{Addr: 0x1000, Size: 64})
		require.NotNil(t, m, "New() with a region must return non-nil *Mask")
	})
}
