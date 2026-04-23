//go:build windows

package hook

import (
	"bytes"
	"sync/atomic"
	"syscall"
	"testing"
	"unsafe"

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

	// The h2 trampoline must contain a freshly copied prologue of the real
	// GetTickCount64 (we can read its current first bytes directly from the
	// loaded module — the target is now JMP-patched again, but we captured
	// what the prologue SHOULD be via h1.origBytes while the function was
	// still pristine). If the allocator happened to reuse h1's address for
	// h2 (common under coverage instrumentation: VirtualFree then
	// VirtualAlloc of the same size often reuses the page) the test must
	// still pass — same address is fine as long as the bytes were re-copied
	// cleanly, not residual from h1. Asserting address-inequality would
	// overspecify the Windows allocator; asserting prologue-equality pins
	// the actual correctness property (no residual state).
	stealLen := len(h1.origBytes)
	h2Bytes := unsafe.Slice((*byte)(unsafe.Pointer(h2.Trampoline())), stealLen)
	require.True(t, bytes.Equal(h1.origBytes, h2Bytes),
		"h2 trampoline prologue %x does not match the pristine prologue %x "+
			"— residual state from h1 or stale copy",
		h2Bytes, h1.origBytes)
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
