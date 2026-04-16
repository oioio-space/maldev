//go:build windows

package namedpipe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/api"
)

var (
	procCreateNamedPipeW    = api.Kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe    = api.Kernel32.NewProc("ConnectNamedPipe")
	procDisconnectNamedPipe = api.Kernel32.NewProc("DisconnectNamedPipe")
	procWaitNamedPipeW      = api.Kernel32.NewProc("WaitNamedPipeW")
)

const (
	pipeDuplex       = 0x00000003 // PIPE_ACCESS_DUPLEX
	pipeTypeByte     = 0x00000000 // PIPE_TYPE_BYTE
	pipeReadModeByte = 0x00000000 // PIPE_READMODE_BYTE
	pipeWait         = 0x00000000 // PIPE_WAIT
	pipeMaxInstances = 255
	pipeBufSize      = 64 * 1024
)

// pipeAddr implements net.Addr for named pipes.
type pipeAddr struct{ name string }

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return a.name }

// pipeConn wraps a Windows pipe handle as a net.Conn.
type pipeConn struct {
	handle windows.Handle
	name   string
	mu     sync.Mutex
	closed bool
}

func (c *pipeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()

	var n uint32
	err := windows.ReadFile(c.handle, p, &n, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_BROKEN_PIPE) {
			return 0, io.EOF
		}
		return 0, fmt.Errorf("pipe read: %w", err)
	}
	return int(n), nil
}

func (c *pipeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	c.mu.Unlock()

	var n uint32
	err := windows.WriteFile(c.handle, p, &n, nil)
	if err != nil {
		return 0, fmt.Errorf("pipe write: %w", err)
	}
	return int(n), nil
}

func (c *pipeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return windows.CloseHandle(c.handle)
}

func (c *pipeConn) LocalAddr() net.Addr                { return pipeAddr{c.name} }
func (c *pipeConn) RemoteAddr() net.Addr               { return pipeAddr{c.name} }
func (c *pipeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(_ time.Time) error { return nil }

// Pipe implements transport.Transport over a Windows named pipe.
type Pipe struct {
	name    string
	timeout time.Duration
	conn    *pipeConn
}

// New creates a named pipe transport that will connect to the given pipe name
// (e.g. `\\.\pipe\myc2`).
func New(name string, timeout time.Duration) *Pipe {
	return &Pipe{name: name, timeout: timeout}
}

// Connect dials the named pipe server, waiting up to the configured timeout
// for the pipe to become available. Any existing connection is closed first.
func (p *Pipe) Connect(ctx context.Context) error {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}

	namePtr, err := windows.UTF16PtrFromString(p.name)
	if err != nil {
		return fmt.Errorf("pipe name: %w", err)
	}

	// Wait for the pipe to be available.
	timeoutMs := uint32(p.timeout.Milliseconds())
	if timeoutMs == 0 {
		timeoutMs = 5000
	}
	r1, _, waitErr := procWaitNamedPipeW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(timeoutMs),
	)
	if r1 == 0 {
		return fmt.Errorf("WaitNamedPipe %s: %w", p.name, waitErr)
	}

	// Check context before opening.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	h, err := windows.CreateFile(
		namePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf("CreateFile %s: %w", p.name, err)
	}

	p.conn = &pipeConn{handle: h, name: p.name}
	return nil
}

// Read reads from the pipe connection.
func (p *Pipe) Read(buf []byte) (int, error) {
	if p.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return p.conn.Read(buf)
}

// Write writes to the pipe connection.
func (p *Pipe) Write(buf []byte) (int, error) {
	if p.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return p.conn.Write(buf)
}

// Close closes the pipe connection.
func (p *Pipe) Close() error {
	if p.conn == nil {
		return nil
	}
	err := p.conn.Close()
	p.conn = nil
	return err
}

// RemoteAddr returns the pipe address or nil if not connected.
func (p *Pipe) RemoteAddr() net.Addr {
	if p.conn == nil {
		return nil
	}
	return pipeAddr{p.name}
}

// PipeListener implements transport.Listener over Windows named pipes.
type PipeListener struct {
	name   string
	mu     sync.Mutex
	closed bool
}

// NewListener creates a named pipe listener on the given pipe name
// (e.g. `\\.\pipe\myc2`).
func NewListener(name string) (*PipeListener, error) {
	// Validate that the name can be converted to UTF-16.
	if _, err := windows.UTF16PtrFromString(name); err != nil {
		return nil, fmt.Errorf("pipe name: %w", err)
	}
	return &PipeListener{name: name}, nil
}

// Accept creates a new pipe instance and blocks until a client connects.
// Each call creates a fresh pipe handle, supporting up to 255 concurrent
// instances.
func (l *PipeListener) Accept(ctx context.Context) (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.mu.Unlock()

	namePtr, err := windows.UTF16PtrFromString(l.name)
	if err != nil {
		return nil, fmt.Errorf("pipe name: %w", err)
	}

	h, _, createErr := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(namePtr)),
		pipeDuplex,
		pipeTypeByte|pipeReadModeByte|pipeWait,
		pipeMaxInstances,
		pipeBufSize,
		pipeBufSize,
		0,
		0,
	)
	if h == uintptr(windows.InvalidHandle) {
		return nil, fmt.Errorf("CreateNamedPipe %s: %w", l.name, createErr)
	}
	handle := windows.Handle(h)

	// ConnectNamedPipe blocks until a client connects. Run in a goroutine
	// so we can respect ctx cancellation.
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		r1, _, connErr := procConnectNamedPipe.Call(uintptr(handle), 0)
		if r1 == 0 {
			// ERROR_PIPE_CONNECTED means the client connected between
			// CreateNamedPipe and ConnectNamedPipe -- this is success.
			if errors.Is(connErr, windows.ERROR_PIPE_CONNECTED) {
				ch <- result{nil}
				return
			}
			ch <- result{connErr}
			return
		}
		ch <- result{nil}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			windows.CloseHandle(handle)
			return nil, fmt.Errorf("ConnectNamedPipe %s: %w", l.name, res.err)
		}
		return &pipeConn{handle: handle, name: l.name}, nil
	case <-ctx.Done():
		// Cancel the blocking ConnectNamedPipe by disconnecting + closing.
		procDisconnectNamedPipe.Call(uintptr(handle))
		windows.CloseHandle(handle)
		return nil, ctx.Err()
	}
}

// Close marks the listener as closed. Subsequent Accept calls will return
// net.ErrClosed.
func (l *PipeListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return nil
}

// Addr returns the pipe address.
func (l *PipeListener) Addr() net.Addr {
	return pipeAddr{l.name}
}
