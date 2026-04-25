//go:build windows

package dllhijack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestScanAutoElevate_FindsKnownCandidates runs the real scanner
// against the host's System32. Typical Win10/11 installations carry
// half a dozen auto-elevating binaries (fodhelper, computerdefaults,
// sdclt, WSReset, etc.) whose imports can trigger hijack opportunities
// when the current token has write access to System32 — which is the
// case under admin. Non-admin: 0 opportunities is fine.
func TestScanAutoElevate_FindsKnownCandidates(t *testing.T) {
	opps, err := ScanAutoElevate()
	require.NoError(t, err)
	t.Logf("found %d auto-elevate hijack opportunities", len(opps))

	// Every row must be consistent.
	for _, o := range opps {
		assert.Equal(t, KindAutoElevate, o.Kind)
		assert.True(t, o.AutoElevate, "AutoElevate flag must be set")
		assert.True(t, o.IntegrityGain, "IntegrityGain flag must be set")
		assert.NotEmpty(t, o.BinaryPath)
		assert.NotEmpty(t, o.HijackedDLL)
		assert.NotEmpty(t, o.HijackedPath)
	}

	// Sanity: known auto-elevate binary fodhelper.exe should be detected
	// via direct byte-level check (independent of ScanAutoElevate, to
	// confirm IsAutoElevate works on the real system).
	fod := filepath.Join(systemDirectory(), "fodhelper.exe")
	if b, err := os.ReadFile(fod); err == nil {
		assert.True(t, IsAutoElevate(b), "fodhelper.exe should be flagged auto-elevate")
	}
}
