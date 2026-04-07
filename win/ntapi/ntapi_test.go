//go:build windows

package ntapi

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestNtQuerySystemInformationBasic calls NtQuerySystemInformation with
// SystemBasicInformation (class 0). The required buffer size is probed on the
// first (expected-to-fail) call; the second call uses the exact required size.
// NT returns STATUS_INFO_LENGTH_MISMATCH even when the supplied buffer is
// larger than needed for certain information classes on some Windows builds, so
// using the exact reported retLen is the most portable approach.
func TestNtQuerySystemInformationBasic(t *testing.T) {
	// Probe: a tiny buffer triggers MISMATCH and tells us the required size.
	probe := [4]byte{}
	needed, _ := NtQuerySystemInformation(0, unsafe.Pointer(&probe[0]), uint32(len(probe)))
	if needed == 0 {
		needed = 64 // conservative fallback for SYSTEM_BASIC_INFORMATION
	}

	buf := make([]byte, needed)
	retLen, err := NtQuerySystemInformation(0, unsafe.Pointer(&buf[0]), uint32(len(buf)))
	require.NoError(t, err)
	assert.Greater(t, retLen, uint32(0), "returned length should be non-zero")
	t.Logf("NtQuerySystemInformation(SystemBasicInformation) needed=%d retLen=%d", needed, retLen)
}

// TestNtAllocateVirtualMemoryAndProtect allocates a small RW region in the
// current process, changes its protection to PAGE_READONLY, then frees it.
// This exercises three NT wrappers in sequence without executing any shellcode.
func TestNtAllocateVirtualMemoryAndProtect(t *testing.T) {
	proc, err := windows.GetCurrentProcess()
	require.NoError(t, err)

	const size = 4096
	addr, err := NtAllocateVirtualMemory(proc, 0, size,
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	require.NoError(t, err)
	require.NotZero(t, addr, "allocated address must not be zero")

	// Change protection from RW to RO.
	oldProtect, err := NtProtectVirtualMemory(proc, addr, size, windows.PAGE_READONLY)
	require.NoError(t, err)
	assert.Equal(t, uint32(windows.PAGE_READWRITE), oldProtect,
		"previous protection should be PAGE_READWRITE")

	// Free the allocation via VirtualFree so we do not leak memory.
	err = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	require.NoError(t, err)
}

// TestNtWriteVirtualMemoryEmpty verifies that writing an empty slice is a
// no-op that returns (0, nil) rather than panicking on a nil buffer pointer.
func TestNtWriteVirtualMemoryEmpty(t *testing.T) {
	proc, err := windows.GetCurrentProcess()
	require.NoError(t, err)

	written, err := NtWriteVirtualMemory(proc, 0, []byte{})
	require.NoError(t, err)
	assert.Equal(t, uintptr(0), written)
}

func TestEnumSystemHandles(t *testing.T) {
	buf, count, err := EnumSystemHandles(0)
	require.NoError(t, err)
	defer FreeHandleBuffer(buf)

	assert.Greater(t, count, uintptr(0), "system must have at least one open handle")
}

func TestKernelPointerByHandle(t *testing.T) {
	var tok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok)
	require.NoError(t, err)
	defer tok.Close()

	// The function must locate the handle without error. The kernel pointer
	// itself may be zero when the OS restricts kernel address exposure.
	_, err = KernelPointerByHandle(windows.Handle(tok))
	require.NoError(t, err)
}

func TestFindHandleByType(t *testing.T) {
	var tok windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok)
	require.NoError(t, err)
	defer tok.Close()

	currentPID := windows.GetCurrentProcessId()
	handleVal, err := FindHandleByType(currentPID, windows.Handle(tok))
	require.NoError(t, err)
	assert.NotZero(t, handleVal, "FindHandleByType must return a non-zero handle value")
}
