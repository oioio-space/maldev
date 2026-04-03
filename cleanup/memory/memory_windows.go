//go:build windows

package memory

import (
	"fmt"
	"runtime"
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

// SecureZero overwrites a byte slice with zeros in a way that the compiler
// cannot optimize away. It writes through a volatile-like pointer and calls
// runtime.KeepAlive to prevent dead-store elimination.
func SecureZero(buf []byte) {
	if len(buf) == 0 {
		return
	}
	p := (*byte)(unsafe.Pointer(&buf[0]))
	for i := range buf {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i))) = 0
	}
	runtime.KeepAlive(p)
}
