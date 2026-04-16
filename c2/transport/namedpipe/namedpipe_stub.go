//go:build !windows

package namedpipe

import (
	"context"
	"errors"
	"net"
	"time"
)

var errUnsupported = errors.New("namedpipe: not supported on this platform")

// Pipe implements transport.Transport over a Windows named pipe.
type Pipe struct{}

// New creates a named pipe transport (unsupported on this platform).
func New(_ string, _ time.Duration) *Pipe { return &Pipe{} }

// Connect is not supported on non-Windows platforms.
func (p *Pipe) Connect(_ context.Context) error { return errUnsupported }

// Read is not supported on non-Windows platforms.
func (p *Pipe) Read(_ []byte) (int, error) { return 0, errUnsupported }

// Write is not supported on non-Windows platforms.
func (p *Pipe) Write(_ []byte) (int, error) { return 0, errUnsupported }

// Close is not supported on non-Windows platforms.
func (p *Pipe) Close() error { return errUnsupported }

// RemoteAddr returns nil on non-Windows platforms.
func (p *Pipe) RemoteAddr() net.Addr { return nil }

// PipeListener implements transport.Listener over Windows named pipes.
type PipeListener struct{}

// NewListener is not supported on non-Windows platforms.
func NewListener(_ string) (*PipeListener, error) { return nil, errUnsupported }

// Accept is not supported on non-Windows platforms.
func (l *PipeListener) Accept(_ context.Context) (net.Conn, error) { return nil, errUnsupported }

// Close is not supported on non-Windows platforms.
func (l *PipeListener) Close() error { return errUnsupported }

// Addr returns nil on non-Windows platforms.
func (l *PipeListener) Addr() net.Addr { return nil }
