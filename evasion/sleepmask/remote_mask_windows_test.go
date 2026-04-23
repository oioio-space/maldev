//go:build windows

package sleepmask

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

func TestRemoteInlineStrategy_RoundTrip(t *testing.T) {
	testutil.RequireIntrusive(t)

	pid, cleanup := testutil.SpawnAndResume(t)
	defer cleanup()

	h, err := windows.OpenProcess(
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ,
		false, pid)
	require.NoError(t, err)
	defer windows.CloseHandle(h)

	// Alloc + write canary in the remote process.
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x42, 0x43, 0x44}
	remoteAddr, _, _ := windows.NewLazySystemDLL("kernel32.dll").
		NewProc("VirtualAllocEx").Call(
		uintptr(h), 0, uintptr(len(data)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE)
	require.NotZero(t, remoteAddr)
	var n uintptr
	require.NoError(t, windows.WriteProcessMemory(h, remoteAddr, &data[0], uintptr(len(data)), &n))

	mask := NewRemote(RemoteRegion{Handle: uintptr(h), Addr: remoteAddr, Size: uintptr(len(data))})
	require.NoError(t, mask.Sleep(context.Background(), 50*time.Millisecond))

	got := make([]byte, len(data))
	require.NoError(t, windows.ReadProcessMemory(h, remoteAddr, &got[0], uintptr(len(got)), &n))
	assert.Equal(t, data, got)
}
