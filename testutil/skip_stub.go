//go:build !windows

package testutil

import "testing"

// RequireAdmin skips the test on non-Windows platforms (no equivalent notion).
func RequireAdmin(t *testing.T) {
	t.Helper()
	t.Skip("RequireAdmin: Windows only")
}
