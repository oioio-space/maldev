//go:build linux

package inject

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

func TestProcMemSelfInject(t *testing.T) {
	testutil.RequireIntrusive(t)
	cfg := &Config{Method: MethodProcMem}
	injector, err := NewInjector(cfg)
	require.NoError(t, err)
	err = injector.Inject(testutil.LinuxCanaryX64)
	require.NoError(t, err)
}

func TestPureGoExec(t *testing.T) {
	testutil.RequireIntrusive(t)
	cfg := &Config{Method: MethodPureGoShellcode}
	injector, err := NewInjector(cfg)
	require.NoError(t, err)
	err = injector.Inject(testutil.LinuxCanaryX64)
	require.NoError(t, err)
}
