package shell

import (
	"context"
	"fmt"
	"sync"
)

// Phase represents the current lifecycle phase of a Shell.
type Phase int

const (
	// PhaseIdle is the initial state before Start is called.
	PhaseIdle Phase = iota

	// PhaseConnecting means the shell is attempting to connect.
	PhaseConnecting

	// PhaseConnected means the shell has an active transport connection.
	PhaseConnected

	// PhaseRunning means a shell session is active.
	PhaseRunning

	// PhaseReconnecting means the shell is waiting before a retry.
	PhaseReconnecting

	// PhaseStopped means the shell has terminated.
	PhaseStopped
)

// String returns a human-readable name for the phase.
func (p Phase) String() string {
	switch p {
	case PhaseIdle:
		return "idle"
	case PhaseConnecting:
		return "connecting"
	case PhaseConnected:
		return "connected"
	case PhaseRunning:
		return "running"
	case PhaseReconnecting:
		return "reconnecting"
	case PhaseStopped:
		return "stopped"
	default:
		return fmt.Sprintf("unknown(%d)", int(p))
	}
}

// shellState represents one state in the shell lifecycle.
// Each state knows which transitions are valid and performs
// state-specific logic.
type shellState interface {
	phase() Phase

	// start transitions from idle to the connection loop.
	// Only valid from PhaseIdle.
	start(sm *stateMachine, ctx context.Context) error

	// stop requests a graceful shutdown.
	// Valid from any active phase.
	stop(sm *stateMachine) error
}

// stateMachine manages shell lifecycle transitions.
type stateMachine struct {
	mu       sync.Mutex
	current  shellState
	stopCh   chan struct{}
	doneCh   chan struct{}
	doneOnce sync.Once
	stopOnce sync.Once

	// onChange is called (under lock) whenever the phase changes.
	// Used for testing and monitoring.
	onChange func(from, to Phase)
}

func newStateMachine() *stateMachine {
	return &stateMachine{
		current: &idleState{},
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}
}

// Phase returns the current lifecycle phase (thread-safe).
func (sm *stateMachine) Phase() Phase {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.current.phase()
}

func (sm *stateMachine) transition(to shellState) {
	from := sm.current.phase()
	sm.current = to
	if sm.onChange != nil {
		sm.onChange(from, to.phase())
	}
}

func (sm *stateMachine) markDone() {
	sm.doneOnce.Do(func() { close(sm.doneCh) })
}

func (sm *stateMachine) requestStop() {
	sm.stopOnce.Do(func() { close(sm.stopCh) })
}

// --- State implementations ---

// idleState is the initial state.
type idleState struct{}

func (idleState) phase() Phase { return PhaseIdle }

func (idleState) start(sm *stateMachine, _ context.Context) error {
	sm.transition(&connectingState{})
	return nil
}

func (idleState) stop(_ *stateMachine) error {
	return fmt.Errorf("shell not running")
}

// connectingState means we are attempting a connection.
type connectingState struct{}

func (connectingState) phase() Phase { return PhaseConnecting }

func (connectingState) start(_ *stateMachine, _ context.Context) error {
	return fmt.Errorf("shell already starting")
}

func (connectingState) stop(sm *stateMachine) error {
	sm.requestStop()
	return nil
}

// connectedState means the transport is connected.
type connectedState struct{}

func (connectedState) phase() Phase { return PhaseConnected }

func (connectedState) start(_ *stateMachine, _ context.Context) error {
	return fmt.Errorf("shell already connected")
}

func (connectedState) stop(sm *stateMachine) error {
	sm.requestStop()
	return nil
}

// runningState means a shell session is active.
type runningState struct{}

func (runningState) phase() Phase { return PhaseRunning }

func (runningState) start(_ *stateMachine, _ context.Context) error {
	return fmt.Errorf("shell already running")
}

func (runningState) stop(sm *stateMachine) error {
	sm.requestStop()
	return nil
}

// reconnectingState means we are waiting before retrying.
type reconnectingState struct{}

func (reconnectingState) phase() Phase { return PhaseReconnecting }

func (reconnectingState) start(_ *stateMachine, _ context.Context) error {
	return fmt.Errorf("shell is reconnecting")
}

func (reconnectingState) stop(sm *stateMachine) error {
	sm.requestStop()
	return nil
}

// stoppedState is the terminal state.
type stoppedState struct{}

func (stoppedState) phase() Phase { return PhaseStopped }

func (stoppedState) start(_ *stateMachine, _ context.Context) error {
	return fmt.Errorf("shell already stopped")
}

func (stoppedState) stop(_ *stateMachine) error {
	return fmt.Errorf("shell already stopped")
}
