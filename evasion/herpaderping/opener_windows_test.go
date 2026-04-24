//go:build windows

package herpaderping

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

// TestRun_UsesProvidedOpener verifies that Config.Opener is consulted
// for the payload read. We use a minimal garbage-bytes payload so
// NtCreateSection(SEC_IMAGE) fails deeper in the pipeline; by then the
// payload read has already gone through the Opener. The decoy read
// would come later but is never reached because Run short-circuits on
// the invalid PE — that ordering is pinned by
// TestRun_NoDecoyPath_SingleOpenerCall and by code inspection.
func TestRun_UsesProvidedOpener(t *testing.T) {
	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "payload.bin")
	decoyPath := filepath.Join(dir, "decoy.bin")
	require.NoError(t, os.WriteFile(payloadPath, []byte{0xDE, 0xAD}, 0o600))
	require.NoError(t, os.WriteFile(decoyPath, []byte{0xBE, 0xEF}, 0o600))

	spy := &testutil.SpyOpener{}
	_ = Run(Config{
		PayloadPath: payloadPath,
		TargetPath:  filepath.Join(dir, "target.exe"),
		DecoyPath:   decoyPath,
		Opener:      spy,
	})
	assert.GreaterOrEqual(t, spy.Calls.Load(), int32(1),
		"Opener must be consulted at least once (for the payload read)")
	paths := spy.Paths()
	require.NotEmpty(t, paths)
	assert.Equal(t, payloadPath, paths[0],
		"first Opener call must be for PayloadPath")
}

// TestRun_NoDecoyPath_SingleOpenerCall verifies that when DecoyPath is
// empty (random-decoy mode), the opener is consulted exactly once (for
// the payload only).
func TestRun_NoDecoyPath_SingleOpenerCall(t *testing.T) {
	dir := t.TempDir()
	payloadPath := filepath.Join(dir, "payload.bin")
	require.NoError(t, os.WriteFile(payloadPath, []byte{0xAA, 0xBB}, 0o600))

	spy := &testutil.SpyOpener{}
	_ = Run(Config{
		PayloadPath: payloadPath,
		TargetPath:  filepath.Join(dir, "target.exe"),
		// DecoyPath empty → random decoy, no opener call
		Opener: spy,
	})
	assert.Equal(t, int32(1), spy.Calls.Load(),
		"Opener must be consulted exactly once when DecoyPath is empty")
}

// TestRun_NilOpener_UsesStandardFallback sanity-checks that passing a
// nil Opener (the overwhelmingly common case) does not panic and that
// the existing TestRunMissingPayload contract still holds.
func TestRun_NilOpener_UsesStandardFallback(t *testing.T) {
	err := Run(Config{PayloadPath: "/nonexistent/payload.exe"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read payload")
}
