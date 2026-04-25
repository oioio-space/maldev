//go:build !windows || !amd64

package callstack

import "unsafe"

// LookupFunctionEntry is a non-windows/non-amd64 stub.
func LookupFunctionEntry(_ uintptr) (Frame, error) {
	return Frame{}, ErrUnsupportedPlatform
}

// StandardChain is a non-windows/non-amd64 stub.
func StandardChain() ([]Frame, error) { return nil, ErrUnsupportedPlatform }

// FindReturnGadget is a non-windows/non-amd64 stub.
func FindReturnGadget() (uintptr, error) { return 0, ErrUnsupportedPlatform }

// SpoofCall is a non-windows/non-amd64 stub.
func SpoofCall(_ unsafe.Pointer, _ []Frame, _ ...uintptr) (uintptr, error) {
	return 0, ErrUnsupportedPlatform
}
