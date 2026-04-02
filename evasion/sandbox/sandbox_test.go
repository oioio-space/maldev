//go:build linux || windows

package sandbox

import (
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
}

func TestNewChecker(t *testing.T) {
	checker := NewCheckerDefault()
	require.NotNil(t, checker, "NewCheckerDefault must return a non-nil Checker")
}
