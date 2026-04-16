//go:build !windows

package hook

import "errors"

var errUnsupported = errors.New("hook: not supported on this platform")

// Hook represents an installed inline hook.
type Hook struct{}

// Install hooks a function by address (unsupported on this platform).
func Install(_ uintptr, _ interface{}) (*Hook, error) { return nil, errUnsupported }

// InstallByName resolves and hooks a function (unsupported on this platform).
func InstallByName(_, _ string, _ interface{}) (*Hook, error) { return nil, errUnsupported }

// Remove unhooks the function.
func (h *Hook) Remove() error { return nil }

// Trampoline returns the address to call the original function.
func (h *Hook) Trampoline() uintptr { return 0 }

// Target returns the address of the hooked function.
func (h *Hook) Target() uintptr { return 0 }
