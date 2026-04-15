package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
)

// Listener is the server-side symmetric to Transport.
// It accepts incoming connections from reverse-shell agents.
type Listener interface {
	// Accept blocks until a new connection arrives or ctx is cancelled.
	Accept(ctx context.Context) (net.Conn, error)
	// Close stops accepting new connections.
	Close() error
	// Addr returns the local address being listened on.
	Addr() net.Addr
}

type tcpListener struct{ l net.Listener }

// NewTCPListener creates a plain-TCP Listener on addr (e.g. "0.0.0.0:4444").
func NewTCPListener(addr string) (Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	return &tcpListener{l: l}, nil
}

func (t *tcpListener) Accept(ctx context.Context) (net.Conn, error) {
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := t.l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- c
	}()
	select {
	case c := <-connCh:
		return c, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		t.l.Close()
		return nil, ctx.Err()
	}
}

func (t *tcpListener) Close() error   { return t.l.Close() }
func (t *tcpListener) Addr() net.Addr { return t.l.Addr() }

type tlsListener struct{ l net.Listener }

// NewTLSListener creates a TLS Listener using the provided *tls.Config.
func NewTLSListener(addr string, cfg *tls.Config) (Listener, error) {
	l, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("tls listen %s: %w", addr, err)
	}
	return &tlsListener{l: l}, nil
}

func (t *tlsListener) Accept(ctx context.Context) (net.Conn, error) {
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := t.l.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- c
	}()
	select {
	case c := <-connCh:
		return c, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		t.l.Close()
		return nil, ctx.Err()
	}
}

func (t *tlsListener) Close() error   { return t.l.Close() }
func (t *tlsListener) Addr() net.Addr { return t.l.Addr() }
