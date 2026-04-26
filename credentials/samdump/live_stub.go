//go:build !windows

package samdump

import "errors"

// ErrLiveDump on non-Windows always reports the platform constraint —
// LiveDump itself is Windows-only.
var ErrLiveDump = errors.New("samdump: live dump requires Windows")

// LiveDump is a non-Windows stub. See live_windows.go for the real
// signature contract.
func LiveDump(_ string) (Result, string, string, error) {
	return Result{}, "", "", ErrLiveDump
}
