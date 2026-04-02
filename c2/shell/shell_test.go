package shell

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestShellStopIdempotent verifies that calling Stop multiple times on a Shell
// that is not running does not panic.  The sync.Once guard inside Stop ensures
// the channel is only closed once when a running shell is stopped; when the
// shell is not running, Stop returns an error immediately without touching the
// channel, so repeated calls are always safe.
func TestShellStopIdempotent(t *testing.T) {
	s := New(nil, nil)
	require.NotNil(t, s)

	// Shell is not running — Stop must return an error, not panic.
	err1 := s.Stop()
	assert.Error(t, err1, "Stop on a non-running shell must return an error")

	// Second call must also return an error without panicking.
	err2 := s.Stop()
	assert.Error(t, err2, "second Stop on a non-running shell must return an error")
}

func TestDefaultConfigShell(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)

	assert.NotEmpty(t, cfg.ShellPath, "ShellPath must not be empty")
	assert.Greater(t, int64(cfg.ReconnectWait), int64(0), "ReconnectWait must be positive")
}

func TestNewShell(t *testing.T) {
	s := New(nil, nil)
	require.NotNil(t, s, "New must return a non-nil Shell")
	assert.False(t, s.IsRunning(), "a newly created Shell must not be running")
}
