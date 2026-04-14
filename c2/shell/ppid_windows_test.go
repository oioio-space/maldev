//go:build windows

package shell

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
	"github.com/oioio-space/maldev/win/api"
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

// TestPPIDSpooferFunctional verifies that a child process is actually spawned
// under a different parent (explorer.exe). This is the core PPID spoofing test.
func TestPPIDSpooferFunctional(t *testing.T) {
	testutil.RequireIntrusive(t)

	// Enable SeDebugPrivilege — required for PROCESS_CREATE_PROCESS on other procs.
	var wasEnabled int32
	api.Ntdll.NewProc("RtlAdjustPrivilege").Call(20, 1, 0, uintptr(unsafe.Pointer(&wasEnabled)))

	// Use a process we know we can open — spawn our own notepad as target parent.
	parentCmd := exec.Command("notepad.exe")
	parentCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	require.NoError(t, parentCmd.Start())
	defer parentCmd.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	spoofer := NewPPIDSpooferWithTargets([]string{"notepad.exe"})
	require.NoError(t, spoofer.FindTargetProcess(), "must find our notepad.exe")
	assert.NotZero(t, spoofer.TargetPID(), "target PID must be set")

	attr, parentHandle, err := spoofer.SysProcAttr()
	require.NoError(t, err)
	defer windows.CloseHandle(parentHandle)

	// Spawn cmd.exe /c echo under the spoofed parent (lighter than notepad).
	cmd := exec.Command("cmd.exe", "/c", "echo", "spoofed")
	cmd.SysProcAttr = attr
	if err := cmd.Start(); err != nil {
		// PPID spoofing may be blocked by Exploit Guard / ASR on this OS version.
		t.Skipf("CreateProcess with spoofed parent blocked (Exploit Guard?): %v", err)
	}
	defer cmd.Process.Kill()

	time.Sleep(500 * time.Millisecond)

	// Verify the child's parent PID matches the spoofer's target.
	childPPID, err := ParentPID(uint32(cmd.Process.Pid))
	require.NoError(t, err)
	assert.Equal(t, spoofer.TargetPID(), childPPID,
		"child's parent PID should be the spoofed target, not our process")

	t.Logf("child PID=%d parent PID=%d (spoofed to %s)",
		cmd.Process.Pid, childPPID, spoofer.Targets)
}

func TestIsAdmin(t *testing.T) {
	// Smoke test: must not panic regardless of privilege level.
	_ = IsAdmin()
}
