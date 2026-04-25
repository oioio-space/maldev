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

	// Phase-A filter is strict: every Opportunity names the exact DLL
	// and drop path. Zero is fine (nothing hijackable on this host);
	// any returned row must carry the new fields.
	t.Logf("found %d hijack opportunities", len(opps))
	for _, o := range opps {
		t.Logf("  %s (%q) binary=%s hijackedDLL=%s drop=%s resolved=%s",
			o.ID, o.DisplayName, o.BinaryPath, o.HijackedDLL, o.HijackedPath, o.ResolvedDLL)
		assert.Equal(t, KindService, o.Kind)
		assert.True(t, o.Writable)
		assert.NotEmpty(t, o.ID)
		assert.NotEmpty(t, o.BinaryPath)
		assert.NotEmpty(t, o.SearchDir)
		assert.NotEmpty(t, o.HijackedDLL, "HijackedDLL must be populated")
		assert.NotEmpty(t, o.HijackedPath, "HijackedPath must be populated")
		assert.Equal(t, o.SearchDir, filepath.Dir(o.HijackedPath),
			"HijackedPath must sit inside SearchDir")
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
