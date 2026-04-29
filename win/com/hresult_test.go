//go:build windows

package com

import (
	"strings"
	"testing"
)

func TestErrorOK(t *testing.T) {
	if err := Error("any", 0); err != nil {
		t.Fatalf("S_OK must return nil, got %v", err)
	}
}

func TestErrorNonZero(t *testing.T) {
	err := Error("CallSite", 0x80004005) // E_FAIL
	if err == nil {
		t.Fatal("non-zero HRESULT must return non-nil error")
	}
	got := err.Error()
	if !strings.Contains(got, "CallSite") {
		t.Errorf("error missing stage string: %q", got)
	}
	if !strings.Contains(got, "0x80004005") {
		t.Errorf("error missing 8-hex HRESULT: %q", got)
	}
}
