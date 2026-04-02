package transport

import (
	"context"
	"io"
	"net"
	"time"
)

// TCPTransport implements Transport over plain TCP.
type TCPTransport struct {
	address string
	timeout time.Duration
	conn    net.Conn
}

// NewTCP creates a new TCP transport.
func NewTCP(address string, timeout time.Duration) *TCPTransport {
	return &TCPTransport{
		address: address,
		timeout: timeout,
	}
}

// Connect establishes a TCP connection with timeout and context support.
// Any existing connection is closed before dialing.
func (t *TCPTransport) Connect(ctx context.Context) error {
	if t.conn != nil {
		t.conn.Close()
		t.conn = nil
	}

	dialer := &net.Dialer{
		Timeout: t.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", t.address)
	if err != nil {
		return err
	}

	t.conn = conn
	return nil
}

// Read reads from the connection.
func (t *TCPTransport) Read(p []byte) (int, error) {
	if t.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return t.conn.Read(p)
}

// Write writes to the connection.
func (t *TCPTransport) Write(p []byte) (int, error) {
	if t.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return t.conn.Write(p)
}

// Close closes the connection.
func (t *TCPTransport) Close() error {
	if t.conn == nil {
		return nil
	}
	return t.conn.Close()
}

// RemoteAddr returns the remote address.
func (t *TCPTransport) RemoteAddr() net.Addr {
	if t.conn == nil {
		return nil
	}
	return t.conn.RemoteAddr()
}
