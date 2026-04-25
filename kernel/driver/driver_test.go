package driver

import (
	"errors"
	"testing"
)

// TestSentinelErrorsDistinct guards against accidental aliasing —
// callers rely on errors.Is to dispatch on each sentinel.
func TestSentinelErrorsDistinct(t *testing.T) {
	all := []error{ErrNotImplemented, ErrNotLoaded, ErrPrivilegeRequired}
	for i, a := range all {
		if a == nil {
			t.Fatalf("sentinel[%d] nil", i)
		}
		for j, b := range all {
			if i == j {
				continue
			}
			if errors.Is(a, b) {
				t.Errorf("sentinel[%d] aliases sentinel[%d]: %v == %v", i, j, a, b)
			}
		}
	}
}
