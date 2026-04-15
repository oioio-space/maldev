//go:build windows

package inject

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	"golang.org/x/sys/windows"
)

func TestExecuteCallback_EnumWindows(t *testing.T) {
	testutil.RequireIntrusive(t)

	// Allocate RWX memory and write a minimal stub: xor eax,eax; ret (returns 0 = stop enum).
	sc := testutil.WindowsCanaryX64
	addr, err := windows.VirtualAlloc(0, uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	copy((*[64]byte)(unsafe.Pointer(addr))[:len(sc)], sc)

	err = ExecuteCallback(addr, CallbackEnumWindows)
	assert.NoError(t, err)
}

func TestExecuteCallback_ZeroAddr(t *testing.T) {
	err := ExecuteCallback(0, CallbackEnumWindows)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "zero")
}

func TestExecuteCallback_InvalidMethod(t *testing.T) {
	err := ExecuteCallback(0xDEAD, CallbackMethod(99))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestCallbackMethodString(t *testing.T) {
	tests := []struct {
		method CallbackMethod
		want   string
	}{
		{CallbackEnumWindows, "EnumWindows"},
		{CallbackCreateTimerQueue, "CreateTimerQueueTimer"},
		{CallbackCertEnumSystemStore, "CertEnumSystemStore"},
		{CallbackReadDirectoryChanges, "ReadDirectoryChangesW"},
		{CallbackRtlRegisterWait, "RtlRegisterWait"},
		{CallbackNtNotifyChangeDirectory, "NtNotifyChangeDirectoryFile"},
		{CallbackMethod(99), "Unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.method.String())
	}
}

func allocate(t *testing.T) uintptr {
	t.Helper()
	sc := testutil.WindowsCETStubX64
	addr, err := windows.VirtualAlloc(0, uintptr(len(sc)),
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	var written uintptr
	require.NoError(t, windows.WriteProcessMemory(
		windows.CurrentProcess(), addr, &sc[0], uintptr(len(sc)), &written))
	return addr
}

func TestExecuteCallbackReadDirectoryChanges(t *testing.T) {
	testutil.RequireIntrusive(t)
	sc := allocate(t)
	defer windows.VirtualFree(sc, 0, windows.MEM_RELEASE)
	require.NoError(t, ExecuteCallback(sc, CallbackReadDirectoryChanges))
}

func TestExecuteCallbackRtlRegisterWait(t *testing.T) {
	testutil.RequireIntrusive(t)
	sc := allocate(t)
	defer windows.VirtualFree(sc, 0, windows.MEM_RELEASE)
	require.NoError(t, ExecuteCallback(sc, CallbackRtlRegisterWait))
}

func TestExecuteCallbackNtNotifyChangeDirectory(t *testing.T) {
	testutil.RequireIntrusive(t)
	sc := allocate(t)
	defer windows.VirtualFree(sc, 0, windows.MEM_RELEASE)
	require.NoError(t, ExecuteCallback(sc, CallbackNtNotifyChangeDirectory))
}
