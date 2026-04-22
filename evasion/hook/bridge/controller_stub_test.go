//go:build !windows

package bridge

import (
	"io"
	"testing"
)

// TestControllerStubAll exercises every method on the non-Windows stub so the
// coverage tool sees them covered. Methods are documented no-ops, so we
// assert only that they don't panic and that the documented zero returns
// are produced.
func TestControllerStubAll(t *testing.T) {
	c := Standalone()
	if c == nil {
		t.Fatal("Standalone returned nil")
	}
	c = Connect(nopRWC{})
	if c == nil {
		t.Fatal("Connect returned nil")
	}
	c.Register("cmd", func([]byte) ([]byte, error) { return nil, nil })
	c.SetArgBlock(&ArgBlock{})
	if ab := c.Args(); ab == nil {
		t.Error("Args must return non-nil ArgBlock on stub")
	}
	if ret := c.CallOriginal(1, 2, 3); ret != 0 {
		t.Errorf("CallOriginal stub = %d, want 0", ret)
	}
	c.SetReturn(42)
	c.Log("hello %s", "world")
	c.Exfil("chan", []byte("data"))
	if d := c.Ask("prompt", []byte("ctx")); d != Allow {
		t.Errorf("Ask stub = %v, want Allow", d)
	}
	if err := c.Heartbeat(); err != nil {
		t.Errorf("Heartbeat stub = %v, want nil", err)
	}
	if err := c.Serve(); err != nil {
		t.Errorf("Serve stub = %v, want nil", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close stub = %v, want nil", err)
	}
}

// nopRWC is a minimal io.ReadWriteCloser for Connect's signature.
type nopRWC struct{}

func (nopRWC) Read(p []byte) (int, error)  { return 0, io.EOF }
func (nopRWC) Write(p []byte) (int, error) { return len(p), nil }
func (nopRWC) Close() error                { return nil }
