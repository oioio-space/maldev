//go:build windows

package dllhijack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanServices(t *testing.T) {
	opps, err := ScanServices()
	require.NoError(t, err)

	// On a stock Win10 the current user typically can't write to any
	// service binary's directory — System32/Program Files are protected.
	// Zero opportunities is the expected common case. If any are found,
	// verify the structured data.
	t.Logf("found %d hijack opportunities", len(opps))
	for _, o := range opps {
		t.Logf("  %s (%q) binary=%s dir=%s", o.ID, o.DisplayName, o.BinaryPath, o.SearchDir)
		assert.Equal(t, KindService, o.Kind)
		assert.True(t, o.Writable)
		assert.NotEmpty(t, o.ID)
		assert.NotEmpty(t, o.BinaryPath)
		assert.NotEmpty(t, o.SearchDir)
	}
}

// TestScanServices_FindsWritableDir verifies the scanner detects a writable
// directory under our control. We can't register a real service without
// admin, so instead we directly probe dirWritable against a temp dir.
func TestDirWritable(t *testing.T) {
	tmp := t.TempDir()
	assert.True(t, dirWritable(tmp), "temp dir must be writable")

	// A nonexistent directory is not writable (OpenFile would need the
	// parent path to exist).
	missing := filepath.Join(tmp, "does-not-exist")
	assert.False(t, dirWritable(missing))

	// System32 is readable but not writable for the current user (unless
	// running elevated — in which case skip).
	sys32 := filepath.Join(os.Getenv("SystemRoot"), "System32")
	if st, err := os.Stat(sys32); err == nil && st.IsDir() {
		if dirWritable(sys32) {
			t.Skipf("System32 is writable for this session (running as admin?); skipping negative case")
		}
	}
}
