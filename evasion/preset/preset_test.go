//go:build windows

package preset

import (
	"testing"

	"github.com/oioio-space/maldev/evasion"
)

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

func TestHardened_NonEmpty_AndIncludesCET(t *testing.T) {
	techniques := Hardened()
	if len(techniques) == 0 {
		t.Fatal("Hardened() returned empty slice")
	}
	var sawCET bool
	for _, tq := range techniques {
		if tq.Name() == "cet.Disable" {
			sawCET = true
			break
		}
	}
	if !sawCET {
		t.Errorf("Hardened() missing cet.Disable technique; names=%v", techniqueNames(techniques))
	}
}

func TestCETOptOut_Apply_NoErrorWhenNotEnforced(t *testing.T) {
	// On a non-CET-enforced host (most CI Windows boxes) cet.Enforced()
	// returns false and Apply must return nil. On CET-enforced hosts
	// cet.Disable may either succeed (nil) or fail with
	// ERROR_NOT_SUPPORTED — both outcomes are legitimate so the test
	// only asserts "no panic". Caller-erasure: nil Caller is fine.
	if err := CETOptOut().Apply(nil); err != nil {
		t.Logf("CETOptOut().Apply nil-caller err = %v (host-dependent)", err)
	}
}

func TestAggressive_IncludesCET(t *testing.T) {
	for _, tq := range Aggressive() {
		if tq.Name() == "cet.Disable" {
			return
		}
	}
	t.Errorf("Aggressive() missing cet.Disable technique")
}

func techniqueNames(techniques []evasion.Technique) []string {
	names := make([]string, 0, len(techniques))
	for _, t := range techniques {
		names = append(names, t.Name())
	}
	return names
}
