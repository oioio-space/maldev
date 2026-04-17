//go:build windows

package enum

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestThreads(t *testing.T) {
	// Current process should have at least one thread.
	pid := uint32(os.Getpid())
	threads, err := Threads(pid)
	require.NoError(t, err)
	assert.NotEmpty(t, threads, "current process should have threads")
}

// TestSessionIDPopulated verifies that List() sets each process's SessionID
// to the value ProcessIdToSessionId would report directly. Does not assert
// session > 0 (that assumption breaks for SSH-invoked or service-hosted
// runs where the current process lives in session 0).
func TestSessionIDPopulated(t *testing.T) {
	self := uint32(os.Getpid())

	procs, err := List()
	require.NoError(t, err)

	var expectedSession uint32
	require.NoError(t, windows.ProcessIdToSessionId(self, &expectedSession))

	for _, p := range procs {
		if p.PID == self {
			assert.Equal(t, expectedSession, p.SessionID,
				"List() SessionID must match ProcessIdToSessionId for the current process")
			t.Logf("current process SessionID=%d", p.SessionID)
			return
		}
	}
	t.Fatal("current process not found in List()")
}
