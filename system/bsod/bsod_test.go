//go:build windows

package bsod

import (
	"testing"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

func TestTriggerExists(t *testing.T) {
	// Verify the function signature is correct (compile-time check).
	// We do NOT call Trigger() as it would crash the system.
	var fn func(*wsyscall.Caller) error = Trigger
	if fn == nil {
		t.Fatal("Trigger function is nil")
	}
}

func TestProcsLoaded(t *testing.T) {
	if err := procRtlAdjustPrivilege.Find(); err != nil {
		t.Fatalf("RtlAdjustPrivilege not found: %v", err)
	}
}
