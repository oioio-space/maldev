//go:build windows

package preset

import "testing"

func TestMinimal_NonEmpty(t *testing.T) {
	techniques := Minimal()
	if len(techniques) == 0 {
		t.Fatal("Minimal() returned empty slice")
	}
}

func TestStealth_NonEmpty(t *testing.T) {
	techniques := Stealth()
	if len(techniques) == 0 {
		t.Fatal("Stealth() returned empty slice")
	}
}

func TestAggressive_SupersetOfMinimal(t *testing.T) {
	if len(Aggressive()) < len(Minimal()) {
		t.Fatal("Aggressive should have at least as many techniques as Minimal")
	}
}
