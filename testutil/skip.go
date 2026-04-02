package testutil

import (
	"os"
	"runtime"
	"testing"
)

// RequireWindows skips the test if not running on Windows.
func RequireWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("requires Windows")
	}
}

// RequireLinux skips the test if not running on Linux.
func RequireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
	}
}

// RequireIntrusive skips the test unless MALDEV_INTRUSIVE=1 is set.
func RequireIntrusive(t *testing.T) {
	t.Helper()
	if os.Getenv("MALDEV_INTRUSIVE") == "" {
		t.Skip("intrusive test: set MALDEV_INTRUSIVE=1 to run")
	}
}
