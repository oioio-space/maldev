//go:build linux || windows

package sandbox

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Greater(t, cfg.MinDiskGB, float64(0), "MinDiskGB must be positive")
	assert.Greater(t, cfg.MinRAMGB, float64(0), "MinRAMGB must be positive")
	assert.Greater(t, cfg.MinCPUCores, 0, "MinCPUCores must be positive")
	assert.NotEmpty(t, cfg.BadUsernames, "BadUsernames must not be empty")
	assert.NotEmpty(t, cfg.BadHostnames, "BadHostnames must not be empty")
	assert.NotEmpty(t, cfg.BadProcesses, "BadProcesses must not be empty")
	assert.NotEmpty(t, cfg.DiskPath, "DiskPath must not be empty")
	assert.NotZero(t, cfg.RequestTimeout, "RequestTimeout must be set")
	assert.True(t, cfg.StopOnFirst, "StopOnFirst should default to true")
	assert.Equal(t, 15, cfg.MinProcesses)
	assert.NotEmpty(t, cfg.ConnectivityURL)
}

func TestNew(t *testing.T) {
	checker := New(DefaultConfig())
	require.NotNil(t, checker, "New must return a non-nil Checker")
}

func TestIsSandboxedAcceptsContext(t *testing.T) {
	checker := New(DefaultConfig())
	ctx := context.Background()
	// Smoke test: just ensure the call compiles and runs without panic.
	_, _, _ = checker.IsSandboxed(ctx)
}

func TestHasEnoughDisk(t *testing.T) {
	checker := New(DefaultConfig())
	ok, err := checker.HasEnoughDisk()
	require.NoError(t, err, "HasEnoughDisk must not fail on a real machine")
	// We only check that it runs without error; the result depends on hardware.
	t.Logf("HasEnoughDisk (min %.0f GB): %v", DefaultConfig().MinDiskGB, ok)
}

func TestHasEnoughRAM(t *testing.T) {
	checker := New(DefaultConfig())
	ok, err := checker.HasEnoughRAM()
	require.NoError(t, err, "HasEnoughRAM must not fail on a real machine")
	t.Logf("HasEnoughRAM (min %.0f GB): %v", DefaultConfig().MinRAMGB, ok)
}

func TestHasEnoughCPU(t *testing.T) {
	checker := New(DefaultConfig())
	ok := checker.HasEnoughCPU()
	// Any modern dev machine has >= 2 cores.
	t.Logf("HasEnoughCPU (min %d cores): %v", DefaultConfig().MinCPUCores, ok)
}

func TestRAMBytes(t *testing.T) {
	checker := New(DefaultConfig())
	ram, err := checker.RAMBytes()
	require.NoError(t, err, "RAMBytes must not fail")
	assert.Greater(t, ram, uint64(0), "RAMBytes must return a positive value")
	t.Logf("RAMBytes: %d (%.1f GB)", ram, float64(ram)/(1024*1024*1024))
}

func TestIsSandboxedReturnTypes(t *testing.T) {
	checker := New(DefaultConfig())
	ctx := context.Background()
	sandboxed, reason, err := checker.IsSandboxed(ctx)
	require.NoError(t, err, "IsSandboxed must not return error on real machine")
	// Verify the return types are correct regardless of detection result.
	assert.IsType(t, true, sandboxed)
	assert.IsType(t, "", reason)
	t.Logf("IsSandboxed: detected=%v reason=%q", sandboxed, reason)
}

func TestIsSandboxedStopOnFirstFalse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.StopOnFirst = false
	checker := New(cfg)
	ctx := context.Background()
	sandboxed, reason, err := checker.IsSandboxed(ctx)
	require.NoError(t, err, "IsSandboxed (StopOnFirst=false) must not return error")
	t.Logf("IsSandboxed (full scan): detected=%v reason=%q", sandboxed, reason)
}

func TestCheckAll(t *testing.T) {
	checker := New(DefaultConfig())
	ctx := context.Background()
	results := checker.CheckAll(ctx)
	require.NotEmpty(t, results, "CheckAll must return results")
	// Verify known check names are present.
	names := make(map[string]bool)
	for _, r := range results {
		names[r.Name] = true
		assert.NotEmpty(t, r.Name, "Result.Name must not be empty")
	}
	for _, expected := range []string{"debugger", "vm", "cpu", "ram", "disk", "username", "hostname", "domain", "process", "process_count", "connectivity"} {
		assert.True(t, names[expected], "CheckAll must include %q check", expected)
	}
}

func TestBadUsername(t *testing.T) {
	checker := New(DefaultConfig())
	bad, name, err := checker.BadUsername()
	require.NoError(t, err, "BadUsername must not fail")
	t.Logf("BadUsername: detected=%v name=%q", bad, name)
}

func TestBadHostname(t *testing.T) {
	checker := New(DefaultConfig())
	bad, name, err := checker.BadHostname()
	require.NoError(t, err, "BadHostname must not fail")
	t.Logf("BadHostname: detected=%v name=%q", bad, name)
}
