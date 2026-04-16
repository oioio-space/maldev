//go:build windows

package hook

import (
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestInstall(t *testing.T) {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount")
	require.NoError(t, proc.Find())

	var hookCalled bool
	var h *Hook

	handler := func() uintptr {
		hookCalled = true
		r, _, _ := syscall.SyscallN(h.Trampoline())
		return r
	}

	var err error
	h, err = Install(proc.Addr(), handler)
	require.NoError(t, err)
	defer h.Remove()

	r, _, _ := syscall.SyscallN(proc.Addr())
	require.True(t, hookCalled, "hook handler was not called")
	require.NotZero(t, r, "original should return nonzero tick count")
}

func TestInstallByName(t *testing.T) {
	var hookCalled bool
	var h *Hook

	handler := func() uintptr {
		hookCalled = true
		r, _, _ := syscall.SyscallN(h.Trampoline())
		return r
	}

	var err error
	h, err = InstallByName("kernel32.dll", "GetTickCount", handler)
	require.NoError(t, err)
	defer h.Remove()

	r, _, _ := syscall.SyscallN(h.Target())
	require.True(t, hookCalled)
	require.NotZero(t, r)
}

func TestRemoveRestoresOriginal(t *testing.T) {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount")
	require.NoError(t, proc.Find())

	origBytes := make([]byte, 16)
	copy(origBytes, unsafe.Slice((*byte)(unsafe.Pointer(proc.Addr())), 16))

	h, err := Install(proc.Addr(), func() uintptr { return 0 })
	require.NoError(t, err)

	firstByte := *(*byte)(unsafe.Pointer(proc.Addr()))
	require.Equal(t, byte(0xE9), firstByte, "expected JMP opcode after hook")

	require.NoError(t, h.Remove())

	restoredBytes := make([]byte, 16)
	copy(restoredBytes, unsafe.Slice((*byte)(unsafe.Pointer(proc.Addr())), 16))
	require.Equal(t, origBytes, restoredBytes, "original bytes should be restored")
}

func TestDoubleRemoveIsNoop(t *testing.T) {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount")
	require.NoError(t, proc.Find())

	h, err := Install(proc.Addr(), func() uintptr { return 0 })
	require.NoError(t, err)

	require.NoError(t, h.Remove())
	require.NoError(t, h.Remove())
}

func TestInstallByNameNotFound(t *testing.T) {
	_, err := InstallByName("kernel32.dll", "NonExistentFunc12345", func() uintptr { return 0 })
	require.Error(t, err)
}

func TestTrampolineCallsOriginal(t *testing.T) {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount")
	require.NoError(t, proc.Find())

	// Get a reference tick before hooking.
	refTick, _, _ := syscall.SyscallN(proc.Addr())

	var h *Hook
	handler := func() uintptr {
		r, _, _ := syscall.SyscallN(h.Trampoline())
		return r
	}

	var err error
	h, err = Install(proc.Addr(), handler)
	require.NoError(t, err)
	defer h.Remove()

	tick, _, _ := syscall.SyscallN(proc.Addr())
	require.GreaterOrEqual(t, tick, refTick, "trampoline should return valid tick count")
}
