//go:build windows

package dllhijack

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/persistence/scheduler"
	"github.com/oioio-space/maldev/testutil"
)

func TestValidate_RejectsEmptyCanary(t *testing.T) {
	_, err := Validate(
		Opportunity{Kind: KindService, ID: "foo", HijackedPath: `C:\Dumps\foo.dll`},
		nil,
		ValidateOpts{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "canaryDLL is empty")
}

func TestValidate_RejectsMissingHijackedPath(t *testing.T) {
	_, err := Validate(
		Opportunity{Kind: KindService, ID: "foo"}, // no HijackedPath
		[]byte{0x4d, 0x5a}, // "MZ"
		ValidateOpts{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no HijackedPath")
}

func TestValidate_RejectsKindProcess(t *testing.T) {
	_, err := Validate(
		Opportunity{
			Kind:         KindProcess,
			ID:           "1234",
			HijackedPath: filepath.Join(t.TempDir(), "x.dll"),
		},
		[]byte{0x4d, 0x5a},
		ValidateOpts{Timeout: 200 * time.Millisecond},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KindProcess")
}

// TestValidate_OrchestrationEndToEnd uses a scheduled task whose
// ACTION writes the marker file directly — not a real canary DLL,
// but exercises the full Validate orchestration path (drop → trigger
// → poll → confirm → cleanup).
//
// Requires admin (scheduler Create) and MALDEV_INTRUSIVE because it
// creates + starts a scheduled task on the host.
func TestValidate_OrchestrationEndToEnd(t *testing.T) {
	testutil.RequireIntrusive(t)
	testutil.RequireAdmin(t)

	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}

	// Unique marker name so repeated test runs don't collide.
	markerName := fmt.Sprintf("maldev-canary-test-%d.marker", time.Now().UnixNano())
	markerPath := filepath.Join(programData, markerName)

	// Build a PowerShell action that writes the marker.
	taskName := `\maldev-dllhijack-validate-test`
	script := fmt.Sprintf(
		`-NoProfile -ExecutionPolicy Bypass -Command "'pid=%d marker=%s' | Out-File -Encoding ascii -FilePath '%s'"`,
		os.Getpid(), markerPath, markerPath)

	require.NoError(t, scheduler.Create(taskName,
		scheduler.WithAction(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, script),
		scheduler.WithTriggerDaily(1),
		scheduler.WithHidden(),
	))
	defer scheduler.Delete(taskName) //nolint:errcheck

	// Drop path: anywhere writable; content is just a fake PE sentinel
	// (the task ignores it — it doesn't actually load a DLL, but the
	// Validate code path still drops+cleans it).
	dropPath := filepath.Join(t.TempDir(), "canary.dll")
	canaryBytes := []byte{0x4D, 0x5A, 0x90, 0x00} // "MZ\x90\x00"

	opp := Opportunity{
		Kind:         KindScheduledTask,
		ID:           taskName,
		HijackedPath: dropPath,
	}

	result, err := Validate(opp, canaryBytes, ValidateOpts{
		MarkerGlob:   markerName,
		Timeout:      10 * time.Second,
		PollInterval: 300 * time.Millisecond,
	})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Dropped, "canary should have been dropped")
	assert.True(t, result.Triggered, "task should have been triggered")
	assert.True(t, result.Confirmed, "marker file should have appeared (errors=%v)", result.Errors)
	assert.True(t, result.CleanedUp, "cleanup should have run")
	// MarkerContents intentionally NOT asserted non-empty: the PowerShell
	// action is a multi-step writer (Out-File creates then populates),
	// so Validate's poll can see the file between the two steps and
	// read 0 bytes. A real canary DLL writes atomically via a single
	// WriteFile and would populate this field.

	// Drop path was cleaned up.
	_, err = os.Stat(dropPath)
	assert.True(t, os.IsNotExist(err), "drop path should no longer exist post-cleanup")

	// Marker cleanup has retries, but a stubborn writer could still
	// hold it; we don't hard-fail here.
	if _, err := os.Stat(markerPath); err == nil {
		t.Logf("note: marker %s still exists post-cleanup (writer held it past retry budget)", markerPath)
		_ = os.Remove(markerPath)
	}
}

func TestValidate_KeepCanary(t *testing.T) {
	testutil.RequireIntrusive(t)
	testutil.RequireAdmin(t)

	// Unique drop path so parallel-running tests don't collide.
	dropPath := filepath.Join(t.TempDir(), "keep-canary.dll")
	canaryBytes := []byte{0x4D, 0x5A, 0x90, 0x00}

	// Use a task that does nothing — we only care about the drop+cleanup
	// contract, not whether a marker appears.
	taskName := `\maldev-dllhijack-keepcanary-test`
	require.NoError(t, scheduler.Create(taskName,
		scheduler.WithAction(`C:\Windows\System32\cmd.exe`, "/c", "exit 0"),
		scheduler.WithTriggerDaily(1),
		scheduler.WithHidden(),
	))
	defer scheduler.Delete(taskName) //nolint:errcheck

	opp := Opportunity{
		Kind:         KindScheduledTask,
		ID:           taskName,
		HijackedPath: dropPath,
	}
	result, err := Validate(opp, canaryBytes, ValidateOpts{
		KeepCanary: true,
		Timeout:    500 * time.Millisecond, // we don't care about Confirmed
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Dropped)

	// The drop path MUST still exist because KeepCanary was set.
	_, err = os.Stat(dropPath)
	assert.NoError(t, err, "KeepCanary=true must leave the dropped DLL on disk")

	// Clean up manually.
	_ = os.Remove(dropPath)
}

func TestValidateOpts_Defaults(t *testing.T) {
	var o ValidateOpts
	o.defaults()
	assert.Equal(t, "maldev-canary-*.marker", o.MarkerGlob)
	assert.NotEmpty(t, o.MarkerDir)
	assert.Equal(t, 15*time.Second, o.Timeout)
	assert.Equal(t, 200*time.Millisecond, o.PollInterval)
}
