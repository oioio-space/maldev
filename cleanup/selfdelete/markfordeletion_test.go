//go:build windows

package selfdelete

import (
	"testing"

	"github.com/oioio-space/maldev/testutil"
)

// TestMarkForDeletion calls MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) on the
// current test binary. The binary is only removed at the next reboot; tests
// run inside a VM snapshot so the registry entry has no effect outside the
// VM lifetime. Requires admin because DELAY_UNTIL_REBOOT writes
// PendingFileRenameOperations under HKLM.
func TestMarkForDeletion(t *testing.T) {
	testutil.RequireAdmin(t)
	testutil.RequireManual(t) // mutates HKLM\...\PendingFileRenameOperations

	if err := MarkForDeletion(); err != nil {
		t.Fatalf("MarkForDeletion: %v", err)
	}
	// No post-condition check possible without a reboot. Success is: the
	// MoveFileEx call did not return an error.
}
