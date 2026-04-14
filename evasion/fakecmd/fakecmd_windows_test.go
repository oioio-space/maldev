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

// TestRestoreNoOp verifies Restore is safe to call when Spoof was never called.
func TestRestoreNoOp(t *testing.T) {
	// Ensure clean state (in case prior test left it dirty).
	savedBuffer = 0
	fakeBufferPins = nil

	require.NoError(t, Restore())
}
