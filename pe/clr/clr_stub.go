//go:build !windows

package clr

import (
	"errors"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

var errUnsupported = errors.New("clr: not supported on this platform")

// Runtime is an opaque handle to a loaded CLR runtime.
type Runtime struct{}

// Load returns an error on non-Windows platforms.
func Load(_ *wsyscall.Caller) (*Runtime, error) { return nil, errUnsupported }

// InstalledRuntimes returns an error on non-Windows platforms.
func InstalledRuntimes() ([]string, error) { return nil, errUnsupported }

// ExecuteAssembly returns an error on non-Windows platforms.
func (r *Runtime) ExecuteAssembly(_ []byte, _ []string) error { return errUnsupported }

// ExecuteDLL returns an error on non-Windows platforms.
func (r *Runtime) ExecuteDLL(_ []byte, _, _, _ string) error { return errUnsupported }

// Close is a no-op on non-Windows platforms.
func (r *Runtime) Close() {}
