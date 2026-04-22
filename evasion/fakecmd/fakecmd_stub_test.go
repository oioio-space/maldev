//go:build !windows

package fakecmd

import "testing"

func TestFakecmdStubReturnsErrors(t *testing.T) {
	if err := Spoof("notepad.exe", nil); err == nil {
		t.Error("Spoof stub must return an error")
	}
	if err := Restore(); err == nil {
		t.Error("Restore stub must return an error")
	}
	if err := SpoofPID(1234, "notepad.exe", nil); err == nil {
		t.Error("SpoofPID stub must return an error")
	}
	if got := Current(); got != "" {
		t.Errorf("Current stub = %q, want empty", got)
	}
}
