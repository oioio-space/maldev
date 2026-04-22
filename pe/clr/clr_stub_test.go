//go:build !windows

package clr

import "testing"

func TestClrStubReturnsErrors(t *testing.T) {
	if _, err := Load(nil); err == nil {
		t.Error("Load stub must return an error")
	}
	if _, err := InstalledRuntimes(); err == nil {
		t.Error("InstalledRuntimes stub must return an error")
	}
	if err := InstallRuntimeActivationPolicy(); err == nil {
		t.Error("InstallRuntimeActivationPolicy stub must return an error")
	}
	if err := RemoveRuntimeActivationPolicy(); err == nil {
		t.Error("RemoveRuntimeActivationPolicy stub must return an error")
	}
	// The zero-value Runtime satisfies the method set; exercise it too.
	var r Runtime
	if err := r.ExecuteAssembly([]byte{0x01}, nil); err == nil {
		t.Error("ExecuteAssembly stub must return an error")
	}
	if err := r.ExecuteDLL([]byte{0x01}, "T", "M", "p"); err == nil {
		t.Error("ExecuteDLL stub must return an error")
	}
	// Close is a documented no-op; calling it must not panic.
	r.Close()
}
