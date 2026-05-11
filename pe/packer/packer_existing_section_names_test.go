package packer_test

import (
	"bytes"
	"debug/pe"
	"strings"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// allSectionNames returns every section name in `peBytes`.
// Use on raw inputs (no appended stub).
func allSectionNames(t *testing.T, peBytes []byte) []string {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(peBytes))
	if err != nil {
		t.Fatalf("debug/pe rejected PE: %v", err)
	}
	defer f.Close()
	names := make([]string, 0, len(f.Sections))
	for _, s := range f.Sections {
		names = append(names, s.Name)
	}
	return names
}

// hostSectionNames returns every section name in a packed PE
// output EXCEPT the last (the appended packer stub).
func hostSectionNames(t *testing.T, peBytes []byte) []string {
	t.Helper()
	all := allSectionNames(t, peBytes)
	if len(all) < 2 {
		t.Fatalf("packed output has %d sections, want ≥ 2", len(all))
	}
	return all[:len(all)-1]
}

// TestPackBinary_DefaultExistingSectionNames_PreservesInput pins
// the backwards-compatible default: without opt-in, the host PE's
// section names survive the pack untouched.
func TestPackBinary_DefaultExistingSectionNames_PreservesInput(t *testing.T) {
	input := winhelloFixture(t)
	wantNames := allSectionNames(t, input)
	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	gotNames := hostSectionNames(t, out)
	if len(gotNames) != len(wantNames) {
		t.Fatalf("section count: got %d, want %d", len(gotNames), len(wantNames))
	}
	for i := range gotNames {
		if gotNames[i] != wantNames[i] {
			t.Errorf("section %d name = %q, want %q (regression — Phase 2-F-1 randomization is opt-in)",
				i, gotNames[i], wantNames[i])
		}
	}
}

// TestPackBinary_RandomizeExistingSectionNames_Differs verifies
// the Phase 2-F-1 opt-in: every existing section name should be
// overwritten with a `.xxxxx` random label.
func TestPackBinary_RandomizeExistingSectionNames_Differs(t *testing.T) {
	input := winhelloFixture(t)
	originalNames := allSectionNames(t, input)

	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                        packerpkg.FormatWindowsExe,
		Stage1Rounds:                  3,
		Seed:                          42,
		RandomizeExistingSectionNames: true,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	got := hostSectionNames(t, out)
	if len(got) != len(originalNames) {
		t.Fatalf("section count changed: got %d, want %d", len(got), len(originalNames))
	}
	for i, name := range got {
		if name == originalNames[i] {
			t.Errorf("section %d name unchanged after randomization: %q", i, name)
		}
		if !strings.HasPrefix(name, ".") {
			t.Errorf("section %d name = %q, want '.' prefix (MSVC convention)", i, name)
		}
		if len(name) != 6 {
			t.Errorf("section %d name = %q (len %d), want 6-char form '.xxxxx'", i, name, len(name))
		}
	}
}

// TestPackBinary_RandomizeExistingSectionNames_DeterministicGivenSeed
// preserves the reproducible-build property under the new opt-in.
func TestPackBinary_RandomizeExistingSectionNames_DeterministicGivenSeed(t *testing.T) {
	input := winhelloFixture(t)
	opts := packerpkg.PackBinaryOptions{
		Format:                        packerpkg.FormatWindowsExe,
		Stage1Rounds:                  3,
		Seed:                          999,
		RandomizeExistingSectionNames: true,
	}
	a, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary A: %v", err)
	}
	b, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary B: %v", err)
	}
	an := hostSectionNames(t, a)
	bn := hostSectionNames(t, b)
	for i := range an {
		if an[i] != bn[i] {
			t.Errorf("section %d: same seed produced %q vs %q", i, an[i], bn[i])
		}
	}
}

// TestPackBinary_RandomizeExistingSectionNames_DoesNotTouchStubName
// verifies the composition with Phase 2-A: when ExistingSectionNames
// is on but RandomizeStubSectionName is off, the stub keeps the
// canonical ".mldv" while the host sections are randomised.
func TestPackBinary_RandomizeExistingSectionNames_DoesNotTouchStubName(t *testing.T) {
	input := winhelloFixture(t)
	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                        packerpkg.FormatWindowsExe,
		Stage1Rounds:                  3,
		Seed:                          42,
		RandomizeExistingSectionNames: true,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	if got := lastSectionName(t, out); got != ".mldv" {
		t.Errorf("stub section name = %q, want %q (Phase 2-F-1 must not touch the appended stub)",
			got, ".mldv")
	}
}
