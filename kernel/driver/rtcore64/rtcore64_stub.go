//go:build !windows

package rtcore64

import "github.com/oioio-space/maldev/kernel/driver"

// ErrDriverBytesMissing keeps the symbol exported on non-Windows so
// cross-platform consumers compile.
var ErrDriverBytesMissing = driver.ErrNotImplemented

// Driver is a stub on non-Windows; every method returns
// driver.ErrNotImplemented.
type Driver struct{}

// Install always returns driver.ErrNotImplemented on non-Windows.
func (d *Driver) Install() error { return driver.ErrNotImplemented }

// Uninstall always returns driver.ErrNotImplemented on non-Windows.
func (d *Driver) Uninstall() error { return driver.ErrNotImplemented }

// Loaded always returns false on non-Windows.
func (d *Driver) Loaded() bool { return false }

// ReadKernel always returns driver.ErrNotImplemented on non-Windows.
func (d *Driver) ReadKernel(_ uintptr, _ []byte) (int, error) {
	return 0, driver.ErrNotImplemented
}

// WriteKernel always returns driver.ErrNotImplemented on non-Windows.
func (d *Driver) WriteKernel(_ uintptr, _ []byte) (int, error) {
	return 0, driver.ErrNotImplemented
}
