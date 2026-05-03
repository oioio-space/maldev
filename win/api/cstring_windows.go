//go:build windows

package api

import "unsafe"

// CStringFromPtr reads a NUL-terminated C string from a raw uintptr,
// capping at max bytes so a malformed or non-terminated pointer cannot
// drive the read off the end of mapped memory.
//
// Designed for the common case where Go code receives a uintptr from
// a syscall.NewCallback thunk or a Win32 API and needs to materialise
// the pointed-at string as a Go string. The standard library helper
// windows.BytePtrToString takes a *byte and offers no length cap; this
// helper takes uintptr and bounds the walk, which is the right shape
// for callback-thunk argument handling.
//
// Returns "" when ptr is 0. Returns up to max bytes when no NUL is
// found within the bound; callers can detect that case by checking
// len(result) == max.
func CStringFromPtr(ptr uintptr, max int) string {
	if ptr == 0 {
		return ""
	}
	for n := 0; n < max; n++ {
		if *(*byte)(unsafe.Pointer(ptr + uintptr(n))) == 0 {
			return string(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), n))
		}
	}
	return string(unsafe.Slice((*byte)(unsafe.Pointer(ptr)), max))
}
