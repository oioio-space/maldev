//go:build windows

package evasion

import wsyscall "github.com/oioio-space/maldev/win/syscall"

// AsCaller converts an opaque Caller to *wsyscall.Caller.
// Returns nil when c is nil or not a *wsyscall.Caller, which makes
// downstream code fall back to standard WinAPI calls.
func AsCaller(c Caller) *wsyscall.Caller {
	if c == nil {
		return nil
	}
	wc, _ := c.(*wsyscall.Caller)
	return wc
}
