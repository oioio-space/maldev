//go:build windows

package namedpipe

import (
	"context"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func randomPipeName() string {
	return fmt.Sprintf(`\\.\pipe\maldev-test-%d`, rand.Int63())
}

func TestPipeRoundTrip(t *testing.T) {
	name := randomPipeName()

	ln, err := NewListener(name)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Accept in background.
	type acceptResult struct {
		conn *pipeConn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept(ctx)
		if err != nil {
			acceptCh <- acceptResult{nil, err}
			return
		}
		acceptCh <- acceptResult{c.(*pipeConn), nil}
	}()

	// Give server a moment to create the pipe instance.
	time.Sleep(50 * time.Millisecond)

	client := New(name, 5*time.Second)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer client.Close()

	res := <-acceptCh
	if res.err != nil {
		t.Fatalf("Accept: %v", res.err)
	}
	server := res.conn
	defer server.Close()

	// Client -> Server
	want := []byte("hello from client")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	buf := make([]byte, 256)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("server Read: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("server got %q, want %q", buf[:n], want)
	}

	// Server -> Client
	want = []byte("hello from server")
	if _, err := server.Write(want); err != nil {
		t.Fatalf("server Write: %v", err)
	}
	n, err = client.Read(buf)
	if err != nil {
		t.Fatalf("client Read: %v", err)
	}
	if string(buf[:n]) != string(want) {
		t.Fatalf("client got %q, want %q", buf[:n], want)
	}
}

func TestPipeListenerAddr(t *testing.T) {
	name := randomPipeName()
	ln, err := NewListener(name)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr()
	if addr.Network() != "pipe" {
		t.Fatalf("Network() = %q, want %q", addr.Network(), "pipe")
	}
	if addr.String() != name {
		t.Fatalf("String() = %q, want %q", addr.String(), name)
	}
}

func TestPipeTransportRemoteAddr(t *testing.T) {
	p := New(`\\.\pipe\nonexistent`, time.Second)
	if addr := p.RemoteAddr(); addr != nil {
		t.Fatalf("unconnected RemoteAddr = %v, want nil", addr)
	}
}

func TestPipeListenerClose(t *testing.T) {
	name := randomPipeName()
	ln, err := NewListener(name)
	if err != nil {
		t.Fatalf("NewListener: %v", err)
	}
	ln.Close()

	ctx := context.Background()
	_, err = ln.Accept(ctx)
	if err == nil {
		t.Fatal("Accept on closed listener should fail")
	}
}
