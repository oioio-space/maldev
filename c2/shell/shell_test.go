package shell

import (
	"testing"
	"time"

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

func TestNewShellCurrentPhase(t *testing.T) {
	s := New(nil, nil)
	assert.Equal(t, PhaseIdle, s.CurrentPhase(), "new Shell must start in PhaseIdle")
}

func TestDefaultConfigMaxBackoff(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 5*time.Minute, cfg.MaxBackoff)
	assert.InDelta(t, 0.25, cfg.JitterFactor, 0.001)
}

func TestShellWaitAfterStop(t *testing.T) {
	// Shell never started, so doneCh is open. Manually close it to
	// verify Wait returns.
	s := New(nil, nil)
	s.sm.markDone()

	done := make(chan struct{})
	go func() {
		s.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after markDone")
	}
}
