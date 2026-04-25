//go:build windows

package fakecmd

import (
	"os/exec"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
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

// TestSpoofPID verifies remote-process PEB CommandLine overwrite by
// reading it back through the same PEB walk used by SpoofPID.
func TestSpoofPID(t *testing.T) {
	testutil.RequireAdmin(t)

	proc := exec.Command("notepad.exe")
	if err := proc.Start(); err != nil {
		t.Skipf("cannot start notepad.exe: %v", err)
	}
	t.Cleanup(func() { _ = proc.Process.Kill() })

	// Give notepad a moment to initialize its PEB.
	time.Sleep(300 * time.Millisecond)

	pid := uint32(proc.Process.Pid)
	fake := `C:\Windows\System32\svchost.exe -k netsvcs`

	require.NoError(t, SpoofPID(pid, fake, nil))

	got, err := readRemoteCmdLine(pid)
	require.NoError(t, err)
	require.Equal(t, fake, got)
}

// readRemoteCmdLine reads the PEB CommandLine of the target process, used only
// by TestSpoofPID to verify the overwrite actually landed.
func readRemoteCmdLine(pid uint32) (string, error) {
	const access = windows.PROCESS_VM_READ | windows.PROCESS_QUERY_INFORMATION
	handle, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)

	pbi, err := remoteProcessBasicInfo(handle, nil)
	if err != nil {
		return "", err
	}

	var ppAddr uintptr
	if err := readRemotePtr(handle, pbi.PebBaseAddress+0x20, &ppAddr); err != nil {
		return "", err
	}

	var cmdLine unicodeString
	if err := readRemoteStruct(handle, ppAddr+0x70,
		unsafe.Pointer(&cmdLine), unsafe.Sizeof(cmdLine)); err != nil {
		return "", err
	}

	if cmdLine.Length == 0 || cmdLine.Buffer == 0 {
		return "", nil
	}
	buf := make([]uint16, cmdLine.Length/2)
	if err := windows.ReadProcessMemory(handle, cmdLine.Buffer,
		(*byte)(unsafe.Pointer(&buf[0])),
		uintptr(cmdLine.Length), nil); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf), nil
}
