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

// netListener adapts a net.Listener to the ctx-cancellable Listener interface.
type netListener struct{ l net.Listener }

func (n *netListener) Accept(ctx context.Context) (net.Conn, error) {
	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := n.l.Accept()
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
		n.l.Close()
		return nil, ctx.Err()
	}
}

func (n *netListener) Close() error   { return n.l.Close() }
func (n *netListener) Addr() net.Addr { return n.l.Addr() }

// NewTCPListener creates a plain-TCP Listener on addr (e.g. "0.0.0.0:4444").
func NewTCPListener(addr string) (Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp listen %s: %w", addr, err)
	}
	return &netListener{l: l}, nil
}

// NewTLSListener creates a TLS Listener using the provided *tls.Config.
func NewTLSListener(addr string, cfg *tls.Config) (Listener, error) {
	l, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("tls listen %s: %w", addr, err)
	}
	return &netListener{l: l}, nil
}
