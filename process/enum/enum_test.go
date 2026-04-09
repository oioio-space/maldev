package enum

import (
	"os"
	"runtime"
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

func TestSessionIDPopulated(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("SessionID semantics are Windows-specific (ProcessIdToSessionId)")
	}
	self := uint32(os.Getpid())

	procs, err := List()
	require.NoError(t, err)

	for _, p := range procs {
		if p.PID == self {
			assert.Greater(t, p.SessionID, uint32(0),
				"current process SessionID must be > 0 for interactive sessions")
			return
		}
	}
	t.Fatal("current process not found in List()")
}
