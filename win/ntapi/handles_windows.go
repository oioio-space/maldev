//go:build windows

package ntapi

import (
	"fmt"
	"unsafe"

	"github.com/oioio-space/maldev/win/api"
	"golang.org/x/sys/windows"
)

const (
	// SystemExtendedHandleInformation is the information class for
	// NtQuerySystemInformation that returns all open handles in the system.
	SystemExtendedHandleInformation = 64
)

// EnumSystemHandles enumerates all system handles via
// NtQuerySystemInformation(SystemExtendedHandleInformation).
//
// Returns the raw buffer (must be freed with windows.VirtualFree),
// and the handle count. The buffer starts with a
// SystemHandleInformationEx header followed by HandleCount entries
// of SystemHandle.
//
// maxBufSize caps the growing allocation (default 256 MB if 0).
func EnumSystemHandles(maxBufSize int) (buf unsafe.Pointer, count uintptr, err error) {
	if maxBufSize <= 0 {
		maxBufSize = 256 * 1024 * 1024
	}
	bufLen := uint32(0x10000) // start at 64 KB

	for {
		if bufLen > uint32(maxBufSize) {
			return nil, 0, fmt.Errorf("handle enumeration buffer exceeded %d bytes", maxBufSize)
		}

		addr, allocErr := windows.VirtualAlloc(0, uintptr(bufLen),
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
		if allocErr != nil {
			return nil, 0, fmt.Errorf("VirtualAlloc(%d): %w", bufLen, allocErr)
		}
		ptr := unsafe.Add(unsafe.Pointer(nil), int(addr))

		var retLen uint32
		ntErr := windows.NtQuerySystemInformation(
			SystemExtendedHandleInformation,
			ptr,
			bufLen,
			&retLen,
		)
		if ntErr == windows.STATUS_INFO_LENGTH_MISMATCH {
			windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
			bufLen *= 2
			continue
		}
		if ntErr != nil {
			windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
			return nil, 0, fmt.Errorf("NtQuerySystemInformation: %w", ntErr)
		}

		info := (*api.SystemHandleInformationEx)(ptr)
		return ptr, info.HandleCount, nil
	}
}

// FreeHandleBuffer releases memory returned by EnumSystemHandles.
func FreeHandleBuffer(buf unsafe.Pointer) {
	if buf != nil {
		windows.VirtualFree(uintptr(buf), 0, windows.MEM_RELEASE)
	}
}

// HandleEntry returns the i-th SystemHandle entry from a buffer returned
// by EnumSystemHandles. No bounds checking — caller must ensure i < count.
func HandleEntry(buf unsafe.Pointer, i uintptr) *api.SystemHandle {
	offset := unsafe.Offsetof((*api.SystemHandleInformationEx)(nil).Handles)
	size := unsafe.Sizeof(api.SystemHandle{})
	return (*api.SystemHandle)(unsafe.Add(buf, int(offset+i*size)))
}

// FindHandleByType finds a handle in targetPID that has the same
// ObjectTypeIndex as referenceHandle (which must belong to the current process).
// This is used to locate a specific handle type (e.g., token) in a remote
// process without needing OpenProcessToken (which checks the token DACL).
//
// Returns the handle value from the target process, or an error if not found.
func FindHandleByType(targetPID uint32, referenceHandle windows.Handle) (uintptr, error) {
	currentPID := windows.GetCurrentProcessId()

	buf, count, err := EnumSystemHandles(0)
	if err != nil {
		return 0, fmt.Errorf("enumerate system handles: %w", err)
	}
	defer FreeHandleBuffer(buf)

	// Pass 1: determine ObjectTypeIndex from our reference handle.
	var typeIndex uint16
	for i := uintptr(0); i < count; i++ {
		entry := HandleEntry(buf, i)
		if entry.UniqueProcessId == uintptr(currentPID) &&
			entry.HandleValue == uintptr(referenceHandle) {
			typeIndex = entry.ObjectTypeIndex
			break
		}
	}
	if typeIndex == 0 {
		return 0, fmt.Errorf("reference handle 0x%X not found in current process", referenceHandle)
	}

	// Pass 2: find a matching handle in the target process.
	for i := uintptr(0); i < count; i++ {
		entry := HandleEntry(buf, i)
		if entry.UniqueProcessId == uintptr(targetPID) &&
			entry.ObjectTypeIndex == typeIndex {
			return entry.HandleValue, nil
		}
	}

	return 0, fmt.Errorf("no handle of specified type found")
}

// GetKernelPointerByHandle leaks the kernel-space address of a handle
// object by enumerating all system handles and matching by PID + handle value.
// This is the usermode alternative to a kernel read primitive.
func GetKernelPointerByHandle(handle windows.Handle) (uintptr, error) {
	currentPID := windows.GetCurrentProcessId()

	buf, count, err := EnumSystemHandles(0)
	if err != nil {
		return 0, err
	}
	defer FreeHandleBuffer(buf)

	for i := uintptr(0); i < count; i++ {
		entry := HandleEntry(buf, i)
		if entry.UniqueProcessId == uintptr(currentPID) &&
			entry.HandleValue == uintptr(handle) {
			return entry.Object, nil
		}
	}

	return 0, fmt.Errorf("handle 0x%X not found in system handle table", handle)
}
