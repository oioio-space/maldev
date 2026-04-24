//go:build windows

package dllhijack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/testutil"
)

// TestScanServices_UsesOpener confirms the Opener composition surface
// works end-to-end: a spy opener passed through ScanOpts is consulted
// for every PE file read during the scan.
func TestScanServices_UsesOpener(t *testing.T) {
	spy := &testutil.SpyOpener{}
	_, err := ScanServices(ScanOpts{Opener: spy})
	require.NoError(t, err)
	// Win10 has ~150 services; at least a handful of them have
	// readable binaries. Any positive count proves the opener was
	// consulted in the scanner's inner loop.
	assert.Positive(t, int(spy.Calls.Load()),
		"scanner should have asked the Opener to open at least one service binary")
}

// TestScanOpts_NilOpenerFallsBackToStandard confirms that leaving the
// Opener field nil (or omitting ScanOpts entirely) runs the scanner
// without error using the default os.Open path. No spy assertions —
// the positive path is already covered by the other ScanServices tests.
func TestScanOpts_NilOpenerFallsBackToStandard(t *testing.T) {
	// With explicit nil Opener.
	_, err := ScanServices(ScanOpts{Opener: nil})
	require.NoError(t, err)

	// With explicit stealthopen.Standard.
	_, err = ScanServices(ScanOpts{Opener: &stealthopen.Standard{}})
	require.NoError(t, err)

	// With no ScanOpts at all — variadic zero case, original API.
	_, err = ScanServices()
	require.NoError(t, err)
}
