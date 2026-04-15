//go:build !windows

package fakecmd

import (
	"errors"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

var errUnsupported = errors.New("fakecmd: not supported on this platform")

// Spoof is not supported on non-Windows platforms.
func Spoof(_ string, _ *wsyscall.Caller) error { return errUnsupported }

// Restore is not supported on non-Windows platforms.
func Restore() error { return errUnsupported }

// Current is not supported on non-Windows platforms.
func Current() string { return "" }

// SpoofPID is not supported on non-Windows platforms.
func SpoofPID(_ uint32, _ string, _ *wsyscall.Caller) error { return errUnsupported }
