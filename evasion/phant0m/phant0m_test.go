//go:build windows

package phant0m

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

// requireManual skips unless MALDEV_MANUAL=1 is set.
func requireManual(t *testing.T) {
	t.Helper()
	if os.Getenv("MALDEV_MANUAL") == "" {
		t.Skip("manual test: set MALDEV_MANUAL=1 (requires admin + VM)")
	}
}

// TestKillEventLogThreads terminates Event Log service threads.
//
// PREREQUISITES:
//   - Run as Administrator
//   - Run in a VM (not on your dev machine)
//   - Event Log service must be running: sc query EventLog
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_INTRUSIVE=1 go test ./evasion/phant0m/ -run TestKillEventLogThreads -v
//
// VERIFY:
//
//	After test: wevtutil qe Security /c:1 should fail or return stale events.
//	The Event Log service will appear running but will not write new events.
//
// CLEANUP:
//
//	Restart the Event Log service: net stop EventLog && net start EventLog
//	Or restart the VM.
func TestKillEventLogThreads(t *testing.T) {
	requireManual(t)
	testutil.RequireIntrusive(t)

	// Kill returns an error if no threads were killed or if the operation failed.
	// On success it returns nil, indicating threads were terminated.
	err := Kill(nil)
	require.NoError(t, err)
	// If Kill returned nil, at least one thread was terminated (see Kill source).
	assert.NoError(t, err, "Kill should terminate at least one Event Log thread without error")
	t.Log("Event Log service threads terminated; event logging is now silenced")
}
