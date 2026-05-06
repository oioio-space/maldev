//go:build !windows

package runtime

import "errors"

// ErrNotWindows fires when [LoadPE] / [Prepare] are called on
// a non-Windows host. The reflective loader only ships for
// Windows x64 today; Linux ELF support is on the roadmap.
var ErrNotWindows = errors.New("packer/runtime: reflective loader only supported on Windows")

// mapAndRelocate is the non-Windows stub. Always returns
// ErrNotWindows.
func mapAndRelocate(pe []byte, h *peHeaders) (*PreparedImage, error) {
	return nil, ErrNotWindows
}

// Run is the non-Windows stub.
func (p *PreparedImage) Run() error {
	return ErrNotWindows
}

// Free is a no-op on non-Windows; the loader never allocated
// anything to free.
func (p *PreparedImage) Free() error {
	return nil
}
