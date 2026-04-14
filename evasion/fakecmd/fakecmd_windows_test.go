//go:build windows

package fakecmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSpoofAndRestore verifies the full Spoof → Current → Restore cycle.
// Modifies the current process PEB; safe to run without any special privilege.
func TestSpoofAndRestore(t *testing.T) {
	original := Current()

	err := Spoof(`C:\Windows\System32\svchost.exe -k netsvcs`, nil)
	require.NoError(t, err)
	require.Equal(t, `C:\Windows\System32\svchost.exe -k netsvcs`, Current())

	err = Restore()
	require.NoError(t, err)
	require.Equal(t, original, Current())
}

// TestSpoofIdempotent verifies that calling Spoof twice preserves the original
// for Restore and that the last fake value is visible via Current.
func TestSpoofIdempotent(t *testing.T) {
	original := Current()
	defer Restore() //nolint:errcheck

	require.NoError(t, Spoof("fake1", nil))
	require.Equal(t, "fake1", Current())

	require.NoError(t, Spoof("fake2", nil))
	require.Equal(t, "fake2", Current())

	require.NoError(t, Restore())
	require.Equal(t, original, Current())
}

// TestRestoreNoOp verifies Restore is safe to call when no Spoof is active.
// The second Restore call must be a no-op returning nil.
func TestRestoreNoOp(t *testing.T) {
	require.NoError(t, Spoof(`C:\Windows\System32\svchost.exe`, nil))
	require.NoError(t, Restore())
	// Second call with no active spoof — must be a no-op.
	require.NoError(t, Restore())
}
