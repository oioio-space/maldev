//go:build !windows

package hideprocess

import (
	"testing"
)

// TestPatchProcessMonitorStubReturnsError documents that the non-Windows
// stub is intentionally a no-op with an error return: callers writing
// cross-platform maldev code can branch on err != nil without a GOOS check.
func TestPatchProcessMonitorStubReturnsError(t *testing.T) {
	if err := PatchProcessMonitor(1234, nil); err == nil {
		t.Error("non-Windows stub must return an error, got nil")
	}
}
