//go:build !windows

package fakecmd

import "errors"

var errUnsupported = errors.New("fakecmd: not supported on this platform")

// Spoof is not supported on non-Windows platforms.
func Spoof(_ string, _ interface{}) error { return errUnsupported }

// Restore is not supported on non-Windows platforms.
func Restore() error { return errUnsupported }

// Current is not supported on non-Windows platforms.
func Current() string { return "" }
