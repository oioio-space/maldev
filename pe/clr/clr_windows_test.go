//go:build windows

package clr

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

func TestInstalledRuntimes(t *testing.T) {
	runtimes, err := InstalledRuntimes()
	require.NoError(t, err)
	require.NotEmpty(t, runtimes, "expected at least one .NET runtime installed")
	for _, r := range runtimes {
		t.Logf("runtime: %s", r)
	}
}

// TestLoadAndClose exercises Load via the clrhost subprocess — necessary
// because `go test` does not provide the <exe>.config that mscoree needs
// to honour legacy v2 CLR activation on Win10+.
func TestLoadAndClose(t *testing.T) {
	require.NoError(t, testutil.RunCLROperation(t, "load"))
}

// TestExecuteAssemblyEmpty verifies the validation path — empty input
// must surface an "empty" error — run inside the clrhost subprocess.
func TestExecuteAssemblyEmpty(t *testing.T) {
	require.NoError(t, testutil.RunCLROperation(t, "exec-empty"))
}

func TestInstallAndRemoveRuntimeActivationPolicy(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	cfg := exe + ".config"

	// Remember prior state so we don't clobber a real host config.
	var priorBytes []byte
	priorExists := false
	if data, err := os.ReadFile(cfg); err == nil {
		priorExists = true
		priorBytes = data
		require.NoError(t, os.Remove(cfg))
	}
	defer func() {
		if priorExists {
			_ = os.WriteFile(cfg, priorBytes, 0o644)
		} else {
			_ = os.Remove(cfg)
		}
	}()

	// Install writes the file.
	require.NoError(t, InstallRuntimeActivationPolicy())
	data, err := os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Contains(t, string(data), "useLegacyV2RuntimeActivationPolicy")

	// Second Install is a no-op (file preserved).
	require.NoError(t, InstallRuntimeActivationPolicy())
	data2, err := os.ReadFile(cfg)
	require.NoError(t, err)
	assert.Equal(t, data, data2)

	// Remove deletes it.
	require.NoError(t, RemoveRuntimeActivationPolicy())
	_, err = os.Stat(cfg)
	assert.True(t, os.IsNotExist(err), "config should be gone after Remove")

	// Remove on missing file is not an error.
	require.NoError(t, RemoveRuntimeActivationPolicy())
}

// TestExecuteDLLValidation runs all three validation cases (empty dll,
// missing type, missing method) inside the clrhost subprocess.
func TestExecuteDLLValidation(t *testing.T) {
	require.NoError(t, testutil.RunCLROperation(t, "exec-dll-validation"))
}
