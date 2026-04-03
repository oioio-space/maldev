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
