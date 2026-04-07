//go:build windows

package bsod

import (
	"testing"
)

func TestTriggerExists(t *testing.T) {
	// Verify the function exists and is callable (compile-time check).
	// We do NOT call Trigger() as it would crash the system.
	var fn func() error = Trigger
	if fn == nil {
		t.Fatal("Trigger function is nil")
	}
}

func TestProcsLoaded(t *testing.T) {
	// Verify ntdll procs can be found (they should always exist on Windows).
	if err := procRtlAdjustPrivilege.Find(); err != nil {
		t.Fatalf("RtlAdjustPrivilege not found in ntdll: %v", err)
	}
	if err := procNtRaiseHardError.Find(); err != nil {
		t.Fatalf("NtRaiseHardError not found in ntdll: %v", err)
	}
}
