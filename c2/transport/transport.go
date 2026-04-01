package transport

import (
	"context"
	"io"
	"net"
)

// Transport defines the interface for C2 connections.
type Transport interface {
	io.ReadWriteCloser
	Connect(ctx context.Context) error
	RemoteAddr() net.Addr
}
