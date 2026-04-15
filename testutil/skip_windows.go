//go:build windows

package testutil

import (
	"testing"

	"golang.org/x/sys/windows"
)

// RequireAdmin skips the test if the current process is not elevated.
// Use for tests that call Win32 APIs requiring administrator privileges.
//
// Implemented without importing win/user to avoid an import cycle
// (testutil ← win/user ← win/api ← win/api tests import testutil).
func RequireAdmin(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("requires administrator elevation")
	}
}
