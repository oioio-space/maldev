//go:build windows

package inject

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func TestSelfInjector_WindowsInjector_BeforeInject(t *testing.T) {
	inj, err := NewInjector(&Config{Method: MethodCreateThread})
	require.NoError(t, err)

	si, ok := inj.(SelfInjector)
	require.True(t, ok, "windowsInjector must satisfy SelfInjector")

	r, has := si.InjectedRegion()
	assert.False(t, has)
	assert.Equal(t, Region{}, r)
}

// TestSelfInjector_WindowsInjector_CTSetsRegion confirms that MethodCreateThread
// (self-process, WinAPI path) publishes a usable Region pointing inside a
// committed executable page after a successful Inject.
func TestSelfInjector_WindowsInjector_CTSetsRegion(t *testing.T) {
	sc := testutil.WindowsCanaryX64

	inj, err := NewInjector(&Config{Method: MethodCreateThread})
	require.NoError(t, err)
	require.NoError(t, inj.Inject(sc))

	si := inj.(SelfInjector)
	r, has := si.InjectedRegion()
	require.True(t, has, "CT must publish a region after successful Inject")
	require.NotZero(t, r.Addr, "region address must be non-zero")
	assert.Equal(t, uintptr(len(sc)), r.Size, "region size must match shellcode length")

	var mbi windows.MemoryBasicInformation
	require.NoError(t, windows.VirtualQuery(r.Addr, &mbi, unsafe.Sizeof(mbi)))
	assert.Equal(t, uintptr(windows.MEM_COMMIT), uintptr(mbi.State), "region must be committed")
	exec := mbi.Protect & (windows.PAGE_EXECUTE | windows.PAGE_EXECUTE_READ |
		windows.PAGE_EXECUTE_READWRITE | windows.PAGE_EXECUTE_WRITECOPY)
	assert.NotZero(t, exec, "region must carry an executable protection bit (got 0x%X)", mbi.Protect)
}

// TestSelfInjector_WindowsSyscallInjector_CTSetsRegion exercises the Caller-
// backed self-injection path and confirms it also publishes a valid region.
func TestSelfInjector_WindowsSyscallInjector_CTSetsRegion(t *testing.T) {
	sc := testutil.WindowsCanaryX64

	inj, err := NewWindowsInjector(&WindowsConfig{
		Config:        Config{Method: MethodCreateThread},
		SyscallMethod: wsyscall.MethodIndirect,
	})
	require.NoError(t, err)
	require.NoError(t, inj.Inject(sc))

	si, ok := inj.(SelfInjector)
	require.True(t, ok, "windowsSyscallInjector must satisfy SelfInjector")

	r, has := si.InjectedRegion()
	require.True(t, has)
	require.NotZero(t, r.Addr)
	assert.Equal(t, uintptr(len(sc)), r.Size)
}

// TestSelfInjector_WindowsInjector_CrossProcessReportsNoRegion verifies the
// contract on a cross-process method: without a valid PID the Inject fails
// fast, and (more importantly) InjectedRegion stays false. We do not need
// to actually cross-inject — the code path in question only populates the
// region on the self-process branches, which this test avoids.
func TestSelfInjector_WindowsInjector_CrossProcessReportsNoRegion(t *testing.T) {
	inj, err := NewInjector(&Config{Method: MethodCreateRemoteThread, PID: 0})
	require.NoError(t, err)

	err = inj.Inject(testutil.WindowsCanaryX64)
	require.Error(t, err, "CRT with PID=0 must fail early")

	si := inj.(SelfInjector)
	_, has := si.InjectedRegion()
	assert.False(t, has, "cross-process method must not publish a region")
}
