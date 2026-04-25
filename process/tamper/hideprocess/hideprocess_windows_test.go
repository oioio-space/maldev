//go:build windows

package hideprocess

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPatchProcessMonitorInvalidPID(t *testing.T) {
	// PID 0 never exists — OpenProcess should fail with a useful error.
	err := PatchProcessMonitor(0, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "OpenProcess")
}
