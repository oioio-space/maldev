//go:build !windows

package namedpipe

import (
	"context"
	"testing"
	"time"
)

func TestPipeStubReturnsErrors(t *testing.T) {
	p := New(`\\.\pipe\test`, 2*time.Second)
	if p == nil {
		t.Fatal("New returned nil")
	}
	ctx := context.Background()
	if err := p.Connect(ctx); err == nil {
		t.Error("Connect stub must return an error")
	}
	if _, err := p.Read(make([]byte, 8)); err == nil {
		t.Error("Read stub must return an error")
	}
	if _, err := p.Write([]byte("x")); err == nil {
		t.Error("Write stub must return an error")
	}
	if err := p.Close(); err == nil {
		t.Error("Close stub must return an error")
	}
	if addr := p.RemoteAddr(); addr != nil {
		t.Errorf("RemoteAddr stub = %v, want nil", addr)
	}
}

func TestPipeListenerStubReturnsErrors(t *testing.T) {
	ln, err := NewListener(`\\.\pipe\test`)
	if err == nil {
		t.Error("NewListener stub must return an error")
	}
	if ln != nil {
		t.Error("NewListener stub must return nil listener")
	}
	// Zero-value PipeListener still satisfies the method set; exercise it.
	var zero PipeListener
	if _, err := zero.Accept(context.Background()); err == nil {
		t.Error("Accept stub must return an error")
	}
	if err := zero.Close(); err == nil {
		t.Error("Close stub must return an error")
	}
	if addr := zero.Addr(); addr != nil {
		t.Errorf("Addr stub = %v, want nil", addr)
	}
}
