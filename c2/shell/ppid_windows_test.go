//go:build windows

package shell

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParentPID(t *testing.T) {
	pid := uint32(os.Getpid())
	ppid, err := ParentPID(pid)
	require.NoError(t, err)
	assert.Greater(t, ppid, uint32(0), "parent PID must be > 0")
}

func TestParentPIDNotFound(t *testing.T) {
	// PID 0 is System Idle Process; looking for a non-existent PID.
	_, err := ParentPID(99999999)
	assert.Error(t, err)
}

func TestDefaultPPIDTargetsNotEmpty(t *testing.T) {
	assert.NotEmpty(t, DefaultPPIDTargets, "DefaultPPIDTargets must contain at least one entry")
}

func TestNewPPIDSpoofer(t *testing.T) {
	s := NewPPIDSpoofer()
	require.NotNil(t, s, "NewPPIDSpoofer must return a non-nil spoofer")
	assert.Zero(t, s.TargetPID(), "new spoofer must have zero target PID before FindTargetProcess")
}

func TestNewPPIDSpooferWithTargets(t *testing.T) {
	targets := []string{"explorer.exe", "notepad.exe"}
	s := NewPPIDSpooferWithTargets(targets)
	require.NotNil(t, s, "NewPPIDSpooferWithTargets must return a non-nil spoofer")
	assert.Equal(t, targets, s.Targets)
}

func TestPPIDSpooferSysProcAttrNoTarget(t *testing.T) {
	s := NewPPIDSpoofer()
	// Without calling FindTargetProcess, SysProcAttr must fail.
	_, _, err := s.SysProcAttr()
	assert.Error(t, err, "SysProcAttr without target PID must return an error")
}

func TestIsAdmin(t *testing.T) {
	// Smoke test: must not panic regardless of privilege level.
	_ = IsAdmin()
}
