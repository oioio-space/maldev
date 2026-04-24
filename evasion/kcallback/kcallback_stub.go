//go:build !windows || !amd64

package kcallback

import "errors"

// ErrUnsupportedPlatform is returned by every platform-specific entry
// point on non-windows/non-amd64 builds.
var ErrUnsupportedPlatform = errors.New("kcallback: windows/amd64 only")

// NtoskrnlBase is a non-windows stub.
func NtoskrnlBase() (uintptr, error) { return 0, ErrUnsupportedPlatform }

// Enumerate is a non-windows stub.
func Enumerate(_ KernelReader, _ OffsetTable) ([]Callback, error) {
	return nil, ErrUnsupportedPlatform
}

// DriverAt is a non-windows stub.
func DriverAt(_ uintptr) (string, error) { return "", ErrUnsupportedPlatform }
