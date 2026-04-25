//go:build windows

package hwbp

import "testing"

// TestTechniqueFactory asserts the Technique() factory returns a non-nil
// evasion.Technique whose Name() is the documented stable identifier. The
// Apply() path is exercised by TestDetectAll* and TestClearAll* — testing it
// again here would duplicate hardware-breakpoint scaffolding unnecessarily.
func TestTechniqueFactory(t *testing.T) {
	tech := Technique()
	if tech == nil {
		t.Fatal("Technique() returned nil")
	}
	if got := tech.Name(); got != "hwbp:DetectAll" {
		t.Errorf("Name() = %q, want %q", got, "hwbp:DetectAll")
	}
}
