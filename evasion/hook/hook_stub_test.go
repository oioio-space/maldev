//go:build !windows

package hook

import "testing"

func TestHookStubReturnsErrors(t *testing.T) {
	if _, err := Install(0x1000, nil); err == nil {
		t.Error("Install stub must return an error")
	}
	if _, err := InstallByName("ntdll.dll", "NtAllocateVirtualMemory", nil); err == nil {
		t.Error("InstallByName stub must return an error")
	}
	// Options are no-ops but exist to satisfy the variadic API; exercise both.
	opts := []HookOption{WithCaller(nil), WithCleanFirst()}
	for _, opt := range opts {
		var cfg hookConfig
		opt(&cfg) // must not panic
	}
	// Zero-value Hook methods are documented no-ops.
	var h Hook
	if err := h.Remove(); err != nil {
		t.Errorf("Remove stub = %v, want nil", err)
	}
	if addr := h.Trampoline(); addr != 0 {
		t.Errorf("Trampoline stub = %x, want 0", addr)
	}
	if addr := h.Target(); addr != 0 {
		t.Errorf("Target stub = %x, want 0", addr)
	}
}

func TestHookGroupStub(t *testing.T) {
	if _, err := InstallAll(nil); err == nil {
		t.Error("InstallAll stub must return an error")
	}
	var g HookGroup
	if err := g.RemoveAll(); err != nil {
		t.Errorf("RemoveAll stub = %v, want nil", err)
	}
}
