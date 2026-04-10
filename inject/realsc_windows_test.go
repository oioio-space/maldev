//go:build windows

package inject

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// marker file path written by the marker shellcode.
const markerFile = `C:\maldev_test_marker.txt`

func cleanupMarker() {
	os.Remove(markerFile)
}

// TestCreateThread_RealShellcode injects marker shellcode via CreateThread
// and verifies the file was created on disk.
func TestCreateThread_RealShellcode(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)
	cleanupMarker()
	defer cleanupMarker()

	sc := testutil.LoadPayload(t, "marker_x64.bin")

	inj, err := Build().Method(MethodCreateThread).Create()
	require.NoError(t, err)
	require.NoError(t, inj.Inject(sc))

	// cmd.exe needs a moment to write the file.
	time.Sleep(3 * time.Second)
	data, err := os.ReadFile(markerFile)
	require.NoError(t, err, "marker file must exist after injection")
	assert.Contains(t, string(data), "MALDEV_EXEC_OK")
}

// TestCreateThread_DirectSyscall_RealShellcode injects via direct syscall
// and verifies the marker file.
func TestCreateThread_DirectSyscall_RealShellcode(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)
	cleanupMarker()
	defer cleanupMarker()

	sc := testutil.LoadPayload(t, "marker_x64.bin")

	wcfg := &WindowsConfig{
		Config:        Config{Method: MethodCreateThread},
		SyscallMethod: wsyscall.MethodDirect,
	}
	inj, err := NewWindowsInjector(wcfg)
	require.NoError(t, err)
	require.NoError(t, inj.Inject(sc))

	time.Sleep(3 * time.Second)
	data, err := os.ReadFile(markerFile)
	require.NoError(t, err, "marker file must exist after direct syscall injection")
	assert.Contains(t, string(data), "MALDEV_EXEC_OK")
}

// TestCreateThread_IndirectSyscall_RealShellcode uses indirect syscalls.
func TestCreateThread_IndirectSyscall_RealShellcode(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)
	cleanupMarker()
	defer cleanupMarker()

	sc := testutil.LoadPayload(t, "marker_x64.bin")

	wcfg := &WindowsConfig{
		Config:        Config{Method: MethodCreateThread},
		SyscallMethod: wsyscall.MethodIndirect,
	}
	inj, err := NewWindowsInjector(wcfg)
	require.NoError(t, err)
	require.NoError(t, inj.Inject(sc))

	time.Sleep(3 * time.Second)
	data, err := os.ReadFile(markerFile)
	require.NoError(t, err, "marker file must exist after indirect syscall injection")
	assert.Contains(t, string(data), "MALDEV_EXEC_OK")
}

// TestCreateRemoteThread_RealShellcode injects marker shellcode into a
// sacrificial process via CRT and verifies the file.
func TestCreateRemoteThread_RealShellcode(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)
	cleanupMarker()
	defer cleanupMarker()

	sc := testutil.LoadPayload(t, "marker_x64.bin")

	pid, _, cleanup := testutil.SpawnSacrificial(t)
	defer cleanup()

	inj, err := Build().Method(MethodCreateRemoteThread).TargetPID(int(pid)).Create()
	require.NoError(t, err)
	require.NoError(t, inj.Inject(sc))

	time.Sleep(3 * time.Second)
	data, err := os.ReadFile(markerFile)
	require.NoError(t, err, "marker file must exist after CRT injection")
	assert.Contains(t, string(data), "MALDEV_EXEC_OK")
}

// TestFiber_RealShellcode injects via CreateFiber.
func TestFiber_RealShellcode(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)
	cleanupMarker()
	defer cleanupMarker()

	sc := testutil.LoadPayload(t, "marker_x64.bin")

	inj, err := Build().Method(MethodCreateFiber).Create()
	require.NoError(t, err)
	require.NoError(t, inj.Inject(sc))

	time.Sleep(3 * time.Second)
	data, err := os.ReadFile(markerFile)
	require.NoError(t, err, "marker file must exist after fiber injection")
	assert.Contains(t, string(data), "MALDEV_EXEC_OK")
}
