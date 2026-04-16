//go:build !go1.21

// Package memclear provides a version-gated secure memory clearing primitive.
// On Go 1.21+, it delegates to the clear builtin. On older versions it uses
// volatile-style pointer writes that the compiler cannot eliminate as dead stores.
package memclear

import (
	"runtime"
	"unsafe"
)

// Clear zeros the byte slice using volatile-style writes that the compiler
// cannot optimize away. Fallback for Go < 1.21.
func Clear(buf []byte) {
	if len(buf) == 0 {
		return
	}
	p := (*byte)(unsafe.Pointer(&buf[0]))
	for i := range buf {
		*(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i))) = 0
	}
	runtime.KeepAlive(p)
}
