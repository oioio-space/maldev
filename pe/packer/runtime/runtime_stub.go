//go:build !windows && !linux

package runtime

// [ErrNotWindows] is defined cross-platform in elf.go so test
// code can compare against it without build-tagging the assertion.

// mapAndRelocate is the long-tail stub. Always returns ErrNotWindows.
func mapAndRelocate(pe []byte, h *peHeaders) (*PreparedImage, error) {
	return nil, ErrNotWindows
}

// mapAndRelocateELF is the long-tail stub. Always returns ErrNotWindows.
func mapAndRelocateELF(elf []byte, h *elfHeaders) (*PreparedImage, error) {
	return nil, ErrNotWindows
}

// Run is the long-tail stub.
func (p *PreparedImage) Run() error {
	return ErrNotWindows
}

// Free is a no-op on the long-tail stub; the loader never
// allocated anything to free.
func (p *PreparedImage) Free() error {
	return nil
}
