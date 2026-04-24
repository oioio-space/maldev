//go:build !windows || !amd64

package callstack

// LookupFunctionEntry is a non-windows/non-amd64 stub.
func LookupFunctionEntry(_ uintptr) (Frame, error) {
	return Frame{}, ErrUnsupportedPlatform
}
