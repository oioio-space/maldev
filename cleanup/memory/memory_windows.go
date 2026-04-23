//go:build windows

package memory

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WipeAndFree zeros a memory region and releases it. The region must have
// been allocated with VirtualAlloc (MEM_COMMIT). The function first changes
// protection to PAGE_READWRITE, writes zeros, then calls VirtualFree.
func WipeAndFree(addr, size uintptr) error {
	if addr == 0 {
		return fmt.Errorf("address is zero")
	}
	if size == 0 {
		return fmt.Errorf("size is zero")
	}

	// Ensure we can write -- the region may be RX or PAGE_NOACCESS.
	var oldProtect uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_READWRITE, &oldProtect); err != nil {
		return fmt.Errorf("protection change failed: %w", err)
	}

	// Zero the region through a volatile-style write.
	region := unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(size))
	SecureZero(region)

	// Release the pages.
	if err := windows.VirtualFree(addr, 0, windows.MEM_RELEASE); err != nil {
		return fmt.Errorf("memory release failed: %w", err)
	}

	return nil
}
