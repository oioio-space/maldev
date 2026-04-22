//go:build windows

package bridge

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCallOriginalNilArgBlock covers the guard: CallOriginal returns 0 when
// no ArgBlock is registered or the trampoline address is zero. The real
// syscall branch is exercised by the integration tests (RPC matrix) and
// would crash a unit test if we passed an arbitrary address — the guard
// is the only part worth a deterministic assertion.
func TestCallOriginalNilArgBlock(t *testing.T) {
	c := Standalone()
	if got := c.CallOriginal(); got != 0 {
		t.Errorf("CallOriginal with nil ArgBlock = %d, want 0", got)
	}
	// ArgBlock present but TrampolineAddr == 0 — still the guard path.
	c.SetArgBlock(&ArgBlock{})
	if got := c.CallOriginal(1, 2, 3); got != 0 {
		t.Errorf("CallOriginal with zero TrampolineAddr = %d, want 0", got)
	}
}

// TestArgsDefault covers the two branches of Args(): returns an empty
// ArgBlock when none is set, and returns the stored one when SetArgBlock
// has been called.
func TestArgsDefault(t *testing.T) {
	c := Standalone()
	empty := c.Args()
	require.NotNil(t, empty, "Args on fresh Controller must not return nil")
	require.Zero(t, empty.TrampolineAddr)

	ab := &ArgBlock{TrampolineAddr: 0xDEADBEEF, Args: [18]uintptr{1, 2, 3}}
	c.SetArgBlock(ab)
	got := c.Args()
	require.Equal(t, uintptr(0xDEADBEEF), got.TrampolineAddr)
	require.Equal(t, uintptr(1), got.Args[0])
}

// TestSetReturnNoPanic documents the stub-ness of SetReturn: the method
// exists for API-completeness symmetry with Listener.SetReturn but has
// no observable effect on this side. Just guard against a regression
// that would panic.
func TestSetReturnNoPanic(t *testing.T) {
	c := Standalone()
	c.SetReturn(0xCAFE)
	c.SetReturn(0)
}

// TestLogViaTransport closes the coverage gap on Log(): a non-standalone
// Controller must format the payload and ship it over the wire as a
// msgLog frame. The Listener's OnLog hook is the natural observation
// point.
func TestLogViaTransport(t *testing.T) {
	skipIfNonWindowsController(t)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()

	ctrl := Connect(&readWriteCloser{Reader: cr, Writer: cw, Closer: cw})
	lis := NewListener(&readWriteCloser{Reader: sr, Writer: sw, Closer: sw})

	var got atomic.Value
	lis.OnLog(func(msg string) { got.Store(msg) })

	go ctrl.Serve()
	go lis.Serve()

	ctrl.Log("pid=%d dll=%s", 1234, "user32.dll")

	// Allow the event to round-trip; OnLog fires on Serve's dispatch goroutine.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if v, ok := got.Load().(string); ok && v != "" {
			require.Equal(t, "pid=1234 dll=user32.dll", v)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("OnLog never fired; current value: %v", got.Load())
}

// TestLogStandaloneNoop asserts Log on a Standalone Controller is a true
// no-op (doesn't panic, doesn't block on a nil conn, doesn't leak).
func TestLogStandaloneNoop(t *testing.T) {
	c := Standalone()
	// If the guard regresses, this will block forever writing to a nil conn.
	done := make(chan struct{})
	go func() { c.Log("hello"); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Log on Standalone blocked — regression in the standalone guard")
	}
}

// TestExfilStandaloneNoop mirrors TestLogStandaloneNoop for Exfil — same
// code path (standalone || conn == nil early-return).
func TestExfilStandaloneNoop(t *testing.T) {
	c := Standalone()
	done := make(chan struct{})
	go func() { c.Exfil("tag", []byte("data")); close(done) }()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Exfil on Standalone blocked — regression in the standalone guard")
	}
}

// TestAskStandaloneAlwaysAllows covers the Ask() standalone branch
// (returns Allow without any wire traffic).
func TestAskStandaloneAlwaysAllows(t *testing.T) {
	c := Standalone()
	if d := c.Ask("tag", []byte("ctx")); d != Allow {
		t.Errorf("Standalone Ask = %v, want Allow", d)
	}
}
