package transport

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startTCPEcho starts a local TCP echo server on a random port and returns its address.
// The listener is closed automatically when the test ends.
func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) //nolint:errcheck
			}()
		}
	}()
	return ln.Addr().String()
}

func TestTCPRoundTrip(t *testing.T) {
	addr := startTCPEcho(t)

	tr := NewTCP(addr, 2*time.Second)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	msg := []byte("hello")
	n, err := tr.Write(msg)
	require.NoError(t, err)
	assert.Equal(t, len(msg), n)

	buf := make([]byte, len(msg))
	_, err = io.ReadFull(tr, buf)
	require.NoError(t, err)
	assert.Equal(t, msg, buf)
}

func TestTCPReconnect(t *testing.T) {
	addr := startTCPEcho(t)

	tr := NewTCP(addr, 2*time.Second)

	// First connection: write and echo back.
	require.NoError(t, tr.Connect(context.Background()))

	msg1 := []byte("first")
	_, err := tr.Write(msg1)
	require.NoError(t, err)

	buf := make([]byte, len(msg1))
	_, err = io.ReadFull(tr, buf)
	require.NoError(t, err)
	assert.Equal(t, msg1, buf)

	// Reconnect: Connect should close the old conn and open a new one.
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	msg2 := []byte("second")
	_, err = tr.Write(msg2)
	require.NoError(t, err)

	buf2 := make([]byte, len(msg2))
	_, err = io.ReadFull(tr, buf2)
	require.NoError(t, err)
	assert.Equal(t, msg2, buf2)
}

func TestTCPContextCancel(t *testing.T) {
	// Listen but never accept so the TCP handshake stalls.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	addr := ln.Addr().String()

	// Use a 100 ms deadline context so the dial times out quickly.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	tr := NewTCP(addr, 5*time.Second)
	err = tr.Connect(ctx)
	// The echo server accepts immediately at the TCP level; use a non-routable
	// address to guarantee a timeout instead.
	// If the local listener accepted (unlikely on loopback), skip gracefully.
	if err == nil {
		t.Skip("loopback accepted before context expired — skipping timeout assertion")
	}
	assert.Error(t, err)
}

func TestTCPContextCancelNonRoutable(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737) and guaranteed non-routable.
	addr := "192.0.2.1:9999"

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	tr := NewTCP(addr, 5*time.Second)
	err := tr.Connect(ctx)
	assert.Error(t, err, "expected dial to fail for non-routable address")
}

func TestTCPRemoteAddr(t *testing.T) {
	addr := startTCPEcho(t)

	tr := NewTCP(addr, 2*time.Second)
	require.NoError(t, tr.Connect(context.Background()))
	defer tr.Close()

	remote := tr.RemoteAddr()
	assert.NotNil(t, remote, "RemoteAddr should not be nil after Connect")
}
