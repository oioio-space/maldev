//go:build !windows || !amd64

package callstack

// LookupFunctionEntry is a non-windows/non-amd64 stub.
func LookupFunctionEntry(_ uintptr) (Frame, error) {
	return Frame{}, ErrUnsupportedPlatform
}

// StandardChain is a non-windows/non-amd64 stub.
func StandardChain() ([]Frame, error) { return nil, ErrUnsupportedPlatform }

// FindReturnGadget is a non-windows/non-amd64 stub.
func FindReturnGadget() (uintptr, error) { return 0, ErrUnsupportedPlatform }
