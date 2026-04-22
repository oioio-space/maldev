//go:build !windows

package preset

import "testing"

// TestPresetStubReturnsNil documents that all preset factories return nil
// slices on non-Windows, making this stub a safe no-op when consumers iterate
// with range on the result.
func TestPresetStubReturnsNil(t *testing.T) {
	if got := Minimal(); got != nil {
		t.Errorf("Minimal stub = %v, want nil", got)
	}
	if got := Stealth(); got != nil {
		t.Errorf("Stealth stub = %v, want nil", got)
	}
	if got := Aggressive(); got != nil {
		t.Errorf("Aggressive stub = %v, want nil", got)
	}
}
