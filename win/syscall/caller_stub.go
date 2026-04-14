//go:build !windows

package syscall

// Caller is a stub on non-Windows platforms.
// On Windows, Caller drives direct/indirect syscall dispatch.
type Caller struct{}
