package multicat_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/oioio-space/maldev/c2/multicat"
)

// pipeListener wraps a channel of net.Conn to implement transport.Listener in tests.
type pipeListener struct{ ch chan net.Conn }

func (p *pipeListener) Accept(_ context.Context) (net.Conn, error) {
	c, ok := <-p.ch
	if !ok {
		return nil, io.EOF
	}
	return c, nil
}
func (p *pipeListener) Close() error   { close(p.ch); return nil }
func (p *pipeListener) Addr() net.Addr { return nil }

func TestListenAccept(t *testing.T) {
	ch := make(chan net.Conn, 2)
	l := &pipeListener{ch: ch}
	mgr := multicat.New()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = mgr.Listen(ctx, l) }()

	serverA, clientA := net.Pipe()
	serverB, clientB := net.Pipe()
	ch <- serverA
	ch <- serverB
	go io.WriteString(clientA, "\n")
	go io.WriteString(clientB, "\n")

	time.Sleep(200 * time.Millisecond)

	sessions := mgr.Sessions()
	if len(sessions) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(sessions))
	}
}

func TestSessionsIDSequential(t *testing.T) {
	ch := make(chan net.Conn, 3)
	l := &pipeListener{ch: ch}
	mgr := multicat.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = mgr.Listen(ctx, l) }()

	for i := 0; i < 3; i++ {
		s, c := net.Pipe()
		ch <- s
		go io.WriteString(c, "\n")
	}
	time.Sleep(200 * time.Millisecond)

	ids := make(map[string]bool)
	for _, s := range mgr.Sessions() {
		ids[s.Meta.ID] = true
	}
	for i := 1; i <= 3; i++ {
		want := fmt.Sprintf("%d", i)
		if !ids[want] {
			t.Errorf("missing session ID %q; got %v", want, ids)
		}
	}
}

func TestBannerHostname(t *testing.T) {
	ch := make(chan net.Conn, 1)
	l := &pipeListener{ch: ch}
	mgr := multicat.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = mgr.Listen(ctx, l) }()

	server, client := net.Pipe()
	ch <- server

	go io.WriteString(client, "BANNER:WIN-TARGET\n")
	time.Sleep(200 * time.Millisecond)

	sessions := mgr.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("want 1 session, got %d", len(sessions))
	}
	if sessions[0].Meta.Hostname != "WIN-TARGET" {
		t.Errorf("hostname = %q, want WIN-TARGET", sessions[0].Meta.Hostname)
	}
}

func TestRemoveSession(t *testing.T) {
	ch := make(chan net.Conn, 1)
	l := &pipeListener{ch: ch}
	mgr := multicat.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = mgr.Listen(ctx, l) }()

	server, client := net.Pipe()
	ch <- server
	go io.WriteString(client, "\n")
	time.Sleep(200 * time.Millisecond)

	if err := mgr.Remove("1"); err != nil {
		t.Fatal(err)
	}
	if len(mgr.Sessions()) != 0 {
		t.Fatal("session not removed")
	}
}

func TestEvents(t *testing.T) {
	ch := make(chan net.Conn, 1)
	l := &pipeListener{ch: ch}
	mgr := multicat.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = mgr.Listen(ctx, l) }()

	server, client := net.Pipe()
	ch <- server
	go io.WriteString(client, "\n")

	select {
	case ev := <-mgr.Events():
		if ev.Type != multicat.EventOpened {
			t.Fatalf("want EventOpened, got %v", ev.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no event received")
	}
}

func TestGet(t *testing.T) {
	ch := make(chan net.Conn, 1)
	l := &pipeListener{ch: ch}
	mgr := multicat.New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = mgr.Listen(ctx, l) }()

	server, client := net.Pipe()
	ch <- server
	go io.WriteString(client, "\n")
	time.Sleep(200 * time.Millisecond)

	s, ok := mgr.Get("1")
	if !ok || s == nil {
		t.Fatal("session 1 not found")
	}
	if _, ok := mgr.Get("999"); ok {
		t.Fatal("unexpected session 999")
	}
}
