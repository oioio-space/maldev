//go:build windows

package enum

import (
	"os"
	"strings"
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

func TestImagePath(t *testing.T) {
	self, err := os.Executable()
	require.NoError(t, err)

	got, err := ImagePath(uint32(os.Getpid()))
	require.NoError(t, err)
	assert.True(t, strings.EqualFold(self, got),
		"ImagePath should return %q, got %q", self, got)
}

func TestModules(t *testing.T) {
	mods, err := Modules(uint32(os.Getpid()))
	require.NoError(t, err)
	require.NotEmpty(t, mods, "process has at least one module (the main exe)")

	// First module is always the main exe.
	selfExe, err := os.Executable()
	require.NoError(t, err)
	assert.True(t, strings.EqualFold(mods[0].Path, selfExe),
		"first module should be the main exe: want %q, got %q", selfExe, mods[0].Path)

	foundKernel32 := false
	for _, m := range mods {
		if strings.EqualFold(m.Name, "kernel32.dll") {
			foundKernel32 = true
			break
		}
	}
	assert.True(t, foundKernel32, "kernel32.dll must be in the loaded module list")
}
