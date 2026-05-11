package packer_test

import (
	"bytes"
	"debug/pe"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_DefaultLinkerVersion_PreservesInput pins the
// backwards-compatible default behaviour: when the operator
// doesn't opt in, the input PE's MajorLinker/MinorLinker bytes
// survive the pack unchanged.
func TestPackBinary_DefaultLinkerVersion_PreservesInput(t *testing.T) {
	input := winhelloFixture(t)
	wantMajor, wantMinor := readPELinkerVersion(t, input)

	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	gotMajor, gotMinor := readPELinkerVersion(t, out)
	if gotMajor != wantMajor || gotMinor != wantMinor {
		t.Errorf("default-pack changed LinkerVersion: input %d.%d, output %d.%d",
			wantMajor, wantMinor, gotMajor, gotMinor)
	}
}

// TestPackBinary_RandomizeLinkerVersion_Differs verifies the
// Phase 2-C opt-in: setting RandomizeLinkerVersion=true should
// produce a (major, minor) pair within the plausible MSVC range
// AND differ across seeds.
func TestPackBinary_RandomizeLinkerVersion_Differs(t *testing.T) {
	input := winhelloFixture(t)

	out1, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                 packerpkg.FormatWindowsExe,
		Stage1Rounds:           3,
		Seed:                   42,
		RandomizeLinkerVersion: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=42: %v", err)
	}
	out2, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                 packerpkg.FormatWindowsExe,
		Stage1Rounds:           3,
		Seed:                   1337,
		RandomizeLinkerVersion: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=1337: %v", err)
	}

	maj1, min1 := readPELinkerVersion(t, out1)
	maj2, min2 := readPELinkerVersion(t, out2)

	if maj1 < 12 || maj1 > 15 {
		t.Errorf("seed=42 major %d outside [12, 15]", maj1)
	}
	if maj1 == maj2 && min1 == min2 {
		t.Errorf("seeds 42 and 1337 produced identical LinkerVersion %d.%d", maj1, min1)
	}
}

// TestPackBinary_RandomizeLinkerVersion_DeterministicGivenSeed
// confirms the reproducible-build property.
func TestPackBinary_RandomizeLinkerVersion_DeterministicGivenSeed(t *testing.T) {
	input := winhelloFixture(t)
	opts := packerpkg.PackBinaryOptions{
		Format:                 packerpkg.FormatWindowsExe,
		Stage1Rounds:           3,
		Seed:                   999,
		RandomizeLinkerVersion: true,
	}
	a, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary A: %v", err)
	}
	b, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary B: %v", err)
	}
	maj1, min1 := readPELinkerVersion(t, a)
	maj2, min2 := readPELinkerVersion(t, b)
	if maj1 != maj2 || min1 != min2 {
		t.Errorf("same seed produced different LinkerVersions: %d.%d vs %d.%d",
			maj1, min1, maj2, min2)
	}
}

// readPELinkerVersion extracts MajorLinkerVersion + MinorLinkerVersion
// from the Optional Header via debug/pe (independent path from
// the transform helpers).
func readPELinkerVersion(t *testing.T, peBytes []byte) (uint8, uint8) {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(peBytes))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		return oh.MajorLinkerVersion, oh.MinorLinkerVersion
	}
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		return oh.MajorLinkerVersion, oh.MinorLinkerVersion
	}
	t.Fatal("unknown OptionalHeader type")
	return 0, 0
}
