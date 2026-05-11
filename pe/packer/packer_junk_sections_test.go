package packer_test

import (
	"bytes"
	"debug/pe"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// sectionCount returns the parsed section count of a packed PE.
func sectionCount(t *testing.T, peBytes []byte) int {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(peBytes))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	return len(f.Sections)
}

func TestPackBinary_DefaultJunkSections_None(t *testing.T) {
	input := winhelloFixture(t)
	defaultCount := sectionCount(t, input) + 1 // host + 1 stub
	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	if got := sectionCount(t, out); got != defaultCount {
		t.Errorf("default section count = %d, want %d (regression — RandomizeJunkSections is opt-in)", got, defaultCount)
	}
}

func TestPackBinary_RandomizeJunkSections_AddsBetween1And5(t *testing.T) {
	input := winhelloFixture(t)
	hostCount := sectionCount(t, input)
	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                packerpkg.FormatWindowsExe,
		Stage1Rounds:          3,
		Seed:                  42,
		RandomizeJunkSections: true,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	got := sectionCount(t, out)
	min := hostCount + 1 + 1 // host + stub + at least 1 separator
	max := hostCount + 1 + 5 // host + stub + at most 5 separators
	if got < min || got > max {
		t.Errorf("section count = %d, want in [%d, %d]", got, min, max)
	}
}

// File size on disk must NOT grow — separators are uninitialised.
func TestPackBinary_RandomizeJunkSections_DoesNotGrowFileSize(t *testing.T) {
	input := winhelloFixture(t)
	vanilla, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("vanilla: %v", err)
	}
	withJunk, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                packerpkg.FormatWindowsExe,
		Stage1Rounds:          3,
		Seed:                  42,
		RandomizeJunkSections: true,
	})
	if err != nil {
		t.Fatalf("with junk: %v", err)
	}
	if len(withJunk) != len(vanilla) {
		t.Errorf("file size grew by %d bytes — separators should be BSS-style (uninitialised, no file backing)",
			len(withJunk)-len(vanilla))
	}
}
