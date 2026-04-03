package shell

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase_String(t *testing.T) {
	tests := []struct {
		phase Phase
		want  string
	}{
		{PhaseIdle, "idle"},
		{PhaseConnecting, "connecting"},
		{PhaseConnected, "connected"},
		{PhaseRunning, "running"},
		{PhaseReconnecting, "reconnecting"},
		{PhaseStopped, "stopped"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.phase.String())
	}
}

func TestStateMachine_InitialPhase(t *testing.T) {
	sm := newStateMachine()
	assert.Equal(t, PhaseIdle, sm.Phase())
}

func TestIdleState_Start(t *testing.T) {
	sm := newStateMachine()
	err := sm.current.start(sm, context.Background())
	require.NoError(t, err)
	assert.Equal(t, PhaseConnecting, sm.Phase())
}

func TestIdleState_Stop(t *testing.T) {
	sm := newStateMachine()
	err := sm.current.stop(sm)
	assert.EqualError(t, err, "shell not running")
}

func TestConnectingState_Start(t *testing.T) {
	sm := newStateMachine()
	sm.transition(&connectingState{})
	err := sm.current.start(sm, context.Background())
	assert.EqualError(t, err, "shell already starting")
}

func TestConnectingState_Stop(t *testing.T) {
	sm := newStateMachine()
	sm.transition(&connectingState{})
	err := sm.current.stop(sm)
	require.NoError(t, err)

	// stopCh should be closed.
	select {
	case <-sm.stopCh:
	default:
		t.Fatal("expected stopCh to be closed")
	}
}

func TestRunningState_Start(t *testing.T) {
	sm := newStateMachine()
	sm.transition(&runningState{})
	err := sm.current.start(sm, context.Background())
	assert.EqualError(t, err, "shell already running")
}

func TestRunningState_Stop(t *testing.T) {
	sm := newStateMachine()
	sm.transition(&runningState{})
	err := sm.current.stop(sm)
	require.NoError(t, err)

	select {
	case <-sm.stopCh:
	default:
		t.Fatal("expected stopCh to be closed")
	}
}

func TestStoppedState_Start(t *testing.T) {
	sm := newStateMachine()
	sm.transition(&stoppedState{})
	err := sm.current.start(sm, context.Background())
	assert.EqualError(t, err, "shell already stopped")
}

func TestStoppedState_Stop(t *testing.T) {
	sm := newStateMachine()
	sm.transition(&stoppedState{})
	err := sm.current.stop(sm)
	assert.EqualError(t, err, "shell already stopped")
}

func TestStateMachine_Transition(t *testing.T) {
	sm := newStateMachine()

	var gotFrom, gotTo Phase
	sm.onChange = func(from, to Phase) {
		gotFrom = from
		gotTo = to
	}

	sm.transition(&connectingState{})
	assert.Equal(t, PhaseIdle, gotFrom)
	assert.Equal(t, PhaseConnecting, gotTo)
}

func TestStateMachine_MarkDone(t *testing.T) {
	sm := newStateMachine()
	sm.markDone()

	select {
	case <-sm.doneCh:
	default:
		t.Fatal("expected doneCh to be closed")
	}

	// Calling markDone again should not panic (sync.Once).
	sm.markDone()
}

func TestStateMachine_RequestStop(t *testing.T) {
	sm := newStateMachine()
	sm.requestStop()

	select {
	case <-sm.stopCh:
	default:
		t.Fatal("expected stopCh to be closed")
	}

	// Calling requestStop again should not panic (sync.Once).
	sm.requestStop()
}
