//go:build windows

package dllhijack

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanProcesses(t *testing.T) {
	opps, err := ScanProcesses()
	require.NoError(t, err)
	t.Logf("found %d process-based hijack opportunities", len(opps))
	for _, o := range opps {
		assert.Equal(t, KindProcess, o.Kind)
		assert.NotEmpty(t, o.ID, "ID must be populated (PID)")
		assert.NotEmpty(t, o.BinaryPath)
		assert.NotEmpty(t, o.HijackedDLL)
		assert.NotEmpty(t, o.HijackedPath)
		assert.Equal(t, o.SearchDir, filepath.Dir(o.HijackedPath))
	}
}

func TestScanScheduledTasks(t *testing.T) {
	opps, err := ScanScheduledTasks()
	require.NoError(t, err)
	t.Logf("found %d scheduled-task hijack opportunities", len(opps))
	for _, o := range opps {
		assert.Equal(t, KindScheduledTask, o.Kind)
		assert.NotEmpty(t, o.ID, "ID must be populated (task path)")
		assert.NotEmpty(t, o.BinaryPath)
		assert.NotEmpty(t, o.HijackedDLL)
		assert.NotEmpty(t, o.HijackedPath)
	}
}

func TestScanAll(t *testing.T) {
	all, err := ScanAll()
	// ScanAll surfaces partial errors but still returns collected rows.
	if err != nil {
		t.Logf("ScanAll partial failures: %v", err)
	}
	t.Logf("aggregated %d opportunities across all scanners", len(all))

	// Sanity: each Opportunity belongs to exactly one of the 4 known Kinds.
	valid := map[Kind]bool{
		KindService:       true,
		KindProcess:       true,
		KindScheduledTask: true,
		KindAutoElevate:   true,
	}
	for _, o := range all {
		assert.True(t, valid[o.Kind], "unknown Kind %v", o.Kind)
	}
}
