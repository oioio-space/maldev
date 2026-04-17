package enum

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListNotEmpty(t *testing.T) {
	procs, err := List()
	require.NoError(t, err)
	assert.NotEmpty(t, procs, "List() must return at least one process")
}

func TestListContainsSelf(t *testing.T) {
	self := uint32(os.Getpid())

	procs, err := List()
	require.NoError(t, err)

	for _, p := range procs {
		if p.PID == self {
			return
		}
	}
	t.Errorf("List() did not contain the current process (PID %d)", self)
}

// TestSessionIDPopulated was moved to enum_windows_test.go because it
// needs golang.org/x/sys/windows.ProcessIdToSessionId to compute the
// expected session without assuming interactive (session > 0).

func TestFindByNameNonExistent(t *testing.T) {
	procs, err := FindByName("zzz_nonexistent_process_12345.exe")
	require.NoError(t, err, "FindByName must not error for a missing process")
	assert.Empty(t, procs, "FindByName for a non-existent process must return empty slice")
}

func TestFindByNameCurrentProcess(t *testing.T) {
	// The test binary itself is a running process; its name varies by OS
	// but we can find it via PID match to learn the name, then search by name.
	self := uint32(os.Getpid())
	procs, err := List()
	require.NoError(t, err)

	var selfName string
	for _, p := range procs {
		if p.PID == self {
			selfName = p.Name
			break
		}
	}
	require.NotEmpty(t, selfName, "must find current process name")

	found, err := FindByName(selfName)
	require.NoError(t, err)
	assert.NotEmpty(t, found, "FindByName(%q) must find at least the current process", selfName)

	var pidFound bool
	for _, p := range found {
		if p.PID == self {
			pidFound = true
			break
		}
	}
	assert.True(t, pidFound, "FindByName result must include current process PID")
}

func TestFindByNameCaseInsensitive(t *testing.T) {
	self := uint32(os.Getpid())
	procs, err := List()
	require.NoError(t, err)

	var selfName string
	for _, p := range procs {
		if p.PID == self {
			selfName = p.Name
			break
		}
	}
	require.NotEmpty(t, selfName)

	// Search with uppercased name; FindByName uses EqualFold.
	upper := strings.ToUpper(selfName)
	found, err := FindByName(upper)
	require.NoError(t, err)
	assert.NotEmpty(t, found, "FindByName must be case-insensitive")
}

func TestFindProcessByPID(t *testing.T) {
	self := uint32(os.Getpid())
	p, err := FindProcess(func(_ string, pid, _ uint32) bool {
		return pid == self
	})
	require.NoError(t, err)
	require.NotNil(t, p, "FindProcess must find current process by PID")
	assert.Equal(t, self, p.PID)
	assert.NotEmpty(t, p.Name, "process name must not be empty")
}

func TestFindProcessNoMatch(t *testing.T) {
	_, err := FindProcess(func(_ string, _ uint32, _ uint32) bool {
		return false // never matches
	})
	assert.Error(t, err, "FindProcess must error when no process matches")
}

func TestListProcessesHaveNames(t *testing.T) {
	procs, err := List()
	require.NoError(t, err)

	// At least some processes should have non-empty names.
	var named int
	for _, p := range procs {
		if p.Name != "" {
			named++
		}
	}
	assert.Greater(t, named, 0, "at least some processes must have names")
}
