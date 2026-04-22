//go:build !windows

package session

import "testing"

func TestSessionsStubReturnsErrors(t *testing.T) {
	if _, err := List(); err == nil {
		t.Error("List stub must return an error")
	}
	if _, err := Active(); err == nil {
		t.Error("Active stub must return an error")
	}
	var s SessionState
	if got := s.String(); got != "Unsupported" {
		t.Errorf("SessionState.String stub = %q, want %q", got, "Unsupported")
	}
}
