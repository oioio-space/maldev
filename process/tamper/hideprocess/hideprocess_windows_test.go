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

func TestPatchEnumProcessesInvalidPID(t *testing.T) {
	err := PatchEnumProcesses(0, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "OpenProcess")
}

func TestPatchToolhelpInvalidPID(t *testing.T) {
	err := PatchToolhelp(0, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "OpenProcess")
}

func TestPatchAllInvalidPID(t *testing.T) {
	err := PatchAll(0, nil)
	require.Error(t, err)
	// PatchAll wraps the inner failure with the patch step's name.
	require.Contains(t, err.Error(), "PatchProcessMonitor")
}

func TestBoolFalsePatchBytes(t *testing.T) {
	// Regression guard: the BOOL=FALSE patch is canonically xor eax, eax; ret.
	require.Equal(t, []byte{0x33, 0xC0, 0xC3}, boolFalsePatch)
}
