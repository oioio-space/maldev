//go:build windows

package hook

import (
	"syscall"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// TestReinstallAfterRemove covers the lifecycle where a function is hooked,
// unhooked, then hooked again with a different handler. Catches regressions
// in state cleanup (stale trampoline address, leaked PAGE_EXECUTE_READWRITE
// page, residual bytes) that would make the second Install fail or the
// second trampoline alias to the first one's page.
func TestReinstallAfterRemove(t *testing.T) {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")
	require.NoError(t, proc.Find())

	var firstCalls atomic.Int32
	var h1 *Hook
	handler1 := func() uintptr {
		firstCalls.Add(1)
		r, _, _ := syscall.SyscallN(h1.Trampoline())
		return r
	}
	var err error
	h1, err = Install(proc.Addr(), handler1)
	require.NoError(t, err)

	// Call once: first hook fires.
	r, _, _ := syscall.SyscallN(proc.Addr())
	require.NotZero(t, r, "GetTickCount64 must return >0")
	require.Equal(t, int32(1), firstCalls.Load())

	require.NoError(t, h1.Remove())

	// Call once with no hook installed: both counters must stay at 1.
	syscall.SyscallN(proc.Addr())
	require.Equal(t, int32(1), firstCalls.Load(), "removed hook still fired")

	// Re-install a different handler. The previous trampoline is gone; the
	// second Install must bootstrap fresh allocation + prologue copy.
	var secondCalls atomic.Int32
	var h2 *Hook
	handler2 := func() uintptr {
		secondCalls.Add(1)
		r, _, _ := syscall.SyscallN(h2.Trampoline())
		return r
	}
	h2, err = Install(proc.Addr(), handler2)
	require.NoError(t, err)
	defer h2.Remove()

	r, _, _ = syscall.SyscallN(proc.Addr())
	require.NotZero(t, r)
	require.Equal(t, int32(1), secondCalls.Load(), "re-install handler did not fire")
	require.Equal(t, int32(1), firstCalls.Load(), "first handler fired after remove")

	// Trampoline addresses must differ — they're freshly allocated per Install.
	require.NotEqual(t, h1.Trampoline(), h2.Trampoline(),
		"re-installed hook reused the stale trampoline")
}

// TestInstallOnPristineTargetAfterGroupRollback covers a subtle corruption
// scenario: InstallAll fails midway, triggers rollback, and then a direct
// Install on one of the (now-pristine-again) targets must still succeed.
// Without proper rollback, leftover bytes at the target prevent a clean
// second patch.
func TestInstallOnPristineTargetAfterGroupRollback(t *testing.T) {
	targets := []Target{
		{DLL: "kernel32.dll", Func: "GetTickCount", Handler: func() uintptr { return 0 }},
		// Force rollback by targeting a function that doesn't exist.
		{DLL: "kernel32.dll", Func: "DoesNotExist_CI_SafeStubNameZZZ", Handler: func() uintptr { return 0 }},
	}
	_, err := InstallAll(targets)
	require.Error(t, err, "InstallAll must fail when one target is missing")

	// After rollback, GetTickCount must be restored. A fresh Install must
	// succeed without complaining about residual JMP bytes.
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount")
	require.NoError(t, proc.Find())

	var hit bool
	var h *Hook
	h, err = Install(proc.Addr(), func() uintptr {
		hit = true
		r, _, _ := syscall.SyscallN(h.Trampoline())
		return r
	})
	require.NoError(t, err, "Install after group rollback must succeed")
	defer h.Remove()

	syscall.SyscallN(proc.Addr())
	require.True(t, hit, "handler did not fire after rollback-then-install")
}
