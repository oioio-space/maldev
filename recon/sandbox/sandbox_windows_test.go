//go:build windows

package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiskTotalBytes(t *testing.T) {
	cfg := DefaultConfig()
	size, err := DiskTotalBytes(cfg.DiskPath)
	require.NoError(t, err)
	assert.Greater(t, size, uint64(0), "disk size must be positive")
	t.Logf("disk free bytes for %q: %d (%.1f GB)", cfg.DiskPath, size, float64(size)/1e9)
}
