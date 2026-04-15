//go:build windows

package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
