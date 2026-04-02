//go:build windows

package inject

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func TestCreateThreadSelfInject(t *testing.T) {
	testutil.RequireIntrusive(t)
	cfg := &Config{Method: MethodCreateThread}
	injector, err := NewInjector(cfg)
	require.NoError(t, err)
	err = injector.Inject(testutil.WindowsCanaryX64)
	require.NoError(t, err)
}

func TestCreateRemoteThreadInject(t *testing.T) {
	testutil.RequireIntrusive(t)
	pid, _, cleanup := testutil.SpawnSacrificial(t)
	defer cleanup()
	cfg := &Config{Method: MethodCreateRemoteThread, PID: int(pid)}
	injector, err := NewInjector(cfg)
	require.NoError(t, err)
	err = injector.Inject(testutil.WindowsCanaryX64)
	require.NoError(t, err)
}

func TestSyscallCallerCreateThread(t *testing.T) {
	testutil.RequireIntrusive(t)
	wcfg := &WindowsConfig{
		Config:        Config{Method: MethodCreateThread},
		SyscallMethod: wsyscall.MethodDirect,
	}
	injector, err := NewWindowsInjector(wcfg)
	require.NoError(t, err)
	err = injector.Inject(testutil.WindowsCanaryX64)
	require.NoError(t, err)
}
