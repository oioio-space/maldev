//go:build windows

package scheduler

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/testutil"
)

const testTaskName = `\maldev-test-task`

func TestCreateAndDelete(t *testing.T) {
	testutil.RequireAdmin(t)

	err := Create(testTaskName,
		WithAction(`C:\Windows\System32\notepad.exe`),
		WithTriggerDaily(1),
		WithHidden(),
	)
	require.NoError(t, err)
	defer Delete(testTaskName) //nolint:errcheck

	found, err := Exists(testTaskName)
	require.NoError(t, err)
	assert.True(t, found, "task not found after Create")

	// Actions() should return the binary path we registered.
	actions, err := Actions(testTaskName)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, `C:\Windows\System32\notepad.exe`, actions[0])

	require.NoError(t, Delete(testTaskName))
}

func TestCreateWithTimeAndDelete(t *testing.T) {
	testutil.RequireAdmin(t)

	err := Create(testTaskName,
		WithAction(`C:\Windows\System32\cmd.exe`, "/c", "echo hi"),
		WithTriggerTime(time.Now().Add(24*time.Hour)),
	)
	require.NoError(t, err)
	require.NoError(t, Delete(testTaskName))
}

func TestDeleteNonExistent(t *testing.T) {
	testutil.RequireAdmin(t)
	err := Delete(`\maldev-nonexistent-999`)
	require.Error(t, err)
}

func TestCreateRequiresAction(t *testing.T) {
	err := Create(`\maldev-noaction`, WithTriggerLogon())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WithAction")
}

func TestSplitTaskName(t *testing.T) {
	tests := []struct{ in, folder, leaf string }{
		{`\MyTask`, `\`, `MyTask`},
		{`\Folder\MyTask`, `\Folder`, `MyTask`},
		{`MyTask`, `\`, `MyTask`},
	}
	for _, tt := range tests {
		f, l := splitTaskName(tt.in)
		assert.Equal(t, tt.folder, f, "folder for %q", tt.in)
		assert.Equal(t, tt.leaf, l, "leaf for %q", tt.in)
	}
}

func TestScheduledTaskMechanism(t *testing.T) {
	mech := ScheduledTask(`\maldev-mech`,
		WithAction(`C:\Windows\System32\notepad.exe`),
		WithTriggerLogon(),
	)
	require.NotNil(t, mech)
	assert.Equal(t, `scheduler:\maldev-mech`, mech.Name())
}

func TestList(t *testing.T) {
	testutil.RequireAdmin(t)

	// Skip under non-interactive sessions (SSH = session 0). Task Scheduler
	// on Win10 22H2+ returns inconsistent results from that context:
	// CoInitializeEx occasionally fails with "Fonction incorrecte", and
	// ITaskFolder::GetTasks on the root folder can be empty despite
	// successful RegisterTaskDefinition. Run this test from an interactive
	// session (console / RDP) instead.
	var sid uint32
	_ = windows.ProcessIdToSessionId(uint32(os.Getpid()), &sid)
	if sid == 0 {
		t.Skip("TestList requires an interactive user session (running in service session 0 — e.g. OpenSSH)")
	}

	require.NoError(t, Create(testTaskName,
		WithAction(`C:\Windows\System32\notepad.exe`),
		WithTriggerDaily(1),
	))
	defer Delete(testTaskName) //nolint:errcheck

	tasks, err := List()
	require.NoError(t, err)
	assert.NotEmpty(t, tasks, "root folder should contain at least our test task")

	var found bool
	for _, tk := range tasks {
		if tk.Name == "maldev-test-task" {
			found = true
			assert.NotEmpty(t, tk.Path)
			break
		}
	}
	assert.True(t, found, "List did not return the just-created task")
}

func TestExistsNonExistent(t *testing.T) {
	testutil.RequireAdmin(t)
	found, err := Exists(`\maldev-definitely-not-there-999`)
	require.NoError(t, err)
	assert.False(t, found)
}

func TestRunNonExistent(t *testing.T) {
	testutil.RequireAdmin(t)
	err := Run(`\maldev-nonexistent-run-999`)
	require.Error(t, err)
}
