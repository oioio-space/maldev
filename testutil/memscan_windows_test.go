//go:build windows

package testutil

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestScanProcessMemory(t *testing.T) {
	// Allocate a page, write a known pattern, scan for it.
	pattern := []byte("TESTUTIL_SCAN_MARKER_12345")
	addr, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 4096)
	copy(buf, pattern)

	found, ok := ScanProcessMemory(pattern)
	assert.True(t, ok, "pattern should be found")
	assert.Equal(t, addr, found, "found address should match allocation")
}

func TestModuleBounds(t *testing.T) {
	// ntdll is always loaded.
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	base, end, err := ModuleBounds(ntdll.Handle())
	require.NoError(t, err)
	assert.NotZero(t, base)
	assert.Greater(t, end, base)
}

func TestScanProcessMemoryNotFound(t *testing.T) {
	_, ok := ScanProcessMemory([]byte("THIS_PATTERN_WILL_NEVER_EXIST_9876"))
	assert.False(t, ok)
}

func TestScanProcessMemoryFrom(t *testing.T) {
	pattern := []byte("FROM_SCAN_TEST_MARKER")
	addr, err := windows.VirtualAlloc(0, 4096,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	buf := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 4096)
	copy(buf, pattern)

	// Scan from address 0 should find it.
	found, ok := ScanProcessMemoryFrom(0x10000, pattern)
	assert.True(t, ok)
	assert.Equal(t, addr, found)

	// Scan from addr+1 should NOT find it (starts after the match).
	_, ok = ScanProcessMemoryFrom(addr+1, pattern)
	assert.False(t, ok)
}

func TestScanProcessMemoryEmptyPattern(t *testing.T) {
	_, ok := ScanProcessMemory(nil)
	assert.False(t, ok)
}
