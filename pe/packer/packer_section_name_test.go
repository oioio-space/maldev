package packer_test

import (
	"bytes"
	"debug/pe"
	"os"
	"path/filepath"
	"strings"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_DefaultStubSectionName_IsMldv pins the
// backwards-compatible default behaviour: when the operator
// doesn't opt in to randomization, the appended stub section
// is named ".mldv". Existing operator scripts and YARA-style
// audits depend on this stable name.
func TestPackBinary_DefaultStubSectionName_IsMldv(t *testing.T) {
	input := winhelloFixture(t)
	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	got := lastSectionName(t, out)
	if got != ".mldv" {
		t.Errorf("default stub section name = %q, want %q (regression — Phase 2-A randomization is opt-in)", got, ".mldv")
	}
}

// TestPackBinary_RandomizeStubSectionName_Differs verifies the
// Phase 2-A opt-in: setting RandomizeStubSectionName=true should
// produce a section name that (a) is NOT ".mldv", (b) starts with
// '.', and (c) differs across seeds.
func TestPackBinary_RandomizeStubSectionName_Differs(t *testing.T) {
	input := winhelloFixture(t)

	out1, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                   packerpkg.FormatWindowsExe,
		Stage1Rounds:             3,
		Seed:                     42,
		RandomizeStubSectionName: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=42: %v", err)
	}
	out2, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                   packerpkg.FormatWindowsExe,
		Stage1Rounds:             3,
		Seed:                     1337,
		RandomizeStubSectionName: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=1337: %v", err)
	}

	name1 := lastSectionName(t, out1)
	name2 := lastSectionName(t, out2)

	if name1 == ".mldv" {
		t.Errorf("seed=42 randomized name should not equal default %q", name1)
	}
	if !strings.HasPrefix(name1, ".") {
		t.Errorf("seed=42 randomized name = %q, want '.' prefix (MSVC convention)", name1)
	}
	if name1 == name2 {
		t.Errorf("seeds 42 and 1337 produced identical section names %q — RNG not seeded properly?", name1)
	}
}

// TestPackBinary_RandomizeStubSectionName_DeterministicGivenSeed
// confirms the same seed produces the same section name —
// reproducible-build property the operator relies on for
// deterministic batch packs.
func TestPackBinary_RandomizeStubSectionName_DeterministicGivenSeed(t *testing.T) {
	input := winhelloFixture(t)
	opts := packerpkg.PackBinaryOptions{
		Format:                   packerpkg.FormatWindowsExe,
		Stage1Rounds:             3,
		Seed:                     999,
		RandomizeStubSectionName: true,
	}
	a, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary A: %v", err)
	}
	b, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary B: %v", err)
	}
	if lastSectionName(t, a) != lastSectionName(t, b) {
		t.Errorf("same seed produced different section names: %q vs %q",
			lastSectionName(t, a), lastSectionName(t, b))
	}
}

// winhelloFixture returns the bytes of testdata/winhello.exe,
// or skips the test when the fixture is missing (script-built
// from a Windows VM, not committed to the repo).
func winhelloFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("testdata", "winhello.exe")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("Windows fixture missing (%v); run scripts/build-winhello.sh", err)
	}
	return b
}

// lastSectionName returns the section name of the last entry in
// the PE section table — the one PackBinary just appended.
func lastSectionName(t *testing.T, peBytes []byte) string {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(peBytes))
	if err != nil {
		t.Fatalf("debug/pe rejected packed output: %v", err)
	}
	defer f.Close()
	if len(f.Sections) == 0 {
		t.Fatal("packed output has zero sections")
	}
	return f.Sections[len(f.Sections)-1].Name
}
