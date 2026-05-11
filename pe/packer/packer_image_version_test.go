package packer_test

import (
	"bytes"
	"debug/pe"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

func TestPackBinary_DefaultImageVersion_PreservesInput(t *testing.T) {
	input := winhelloFixture(t)
	wantMajor, wantMinor := readPEImageVersion(t, input)

	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	gotMajor, gotMinor := readPEImageVersion(t, out)
	if gotMajor != wantMajor || gotMinor != wantMinor {
		t.Errorf("default-pack changed ImageVersion: input %d.%d, output %d.%d",
			wantMajor, wantMinor, gotMajor, gotMinor)
	}
}

func TestPackBinary_RandomizeImageVersion_Differs(t *testing.T) {
	input := winhelloFixture(t)

	out1, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                packerpkg.FormatWindowsExe,
		Stage1Rounds:          3,
		Seed:                  42,
		RandomizeImageVersion: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=42: %v", err)
	}
	out2, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:                packerpkg.FormatWindowsExe,
		Stage1Rounds:          3,
		Seed:                  1337,
		RandomizeImageVersion: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=1337: %v", err)
	}

	maj1, min1 := readPEImageVersion(t, out1)
	maj2, min2 := readPEImageVersion(t, out2)

	if maj1 > 9 {
		t.Errorf("seed=42 major %d outside [0, 9]", maj1)
	}
	if maj1 == maj2 && min1 == min2 {
		t.Errorf("seeds 42 and 1337 produced identical ImageVersion %d.%d", maj1, min1)
	}
}

func TestPackBinary_RandomizeImageVersion_DeterministicGivenSeed(t *testing.T) {
	input := winhelloFixture(t)
	opts := packerpkg.PackBinaryOptions{
		Format:                packerpkg.FormatWindowsExe,
		Stage1Rounds:          3,
		Seed:                  999,
		RandomizeImageVersion: true,
	}
	a, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary A: %v", err)
	}
	b, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary B: %v", err)
	}
	maj1, min1 := readPEImageVersion(t, a)
	maj2, min2 := readPEImageVersion(t, b)
	if maj1 != maj2 || min1 != min2 {
		t.Errorf("same seed produced different ImageVersions: %d.%d vs %d.%d",
			maj1, min1, maj2, min2)
	}
}

// readPEImageVersion extracts MajorImageVersion + MinorImageVersion
// from the Optional Header via debug/pe.
func readPEImageVersion(t *testing.T, peBytes []byte) (uint16, uint16) {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(peBytes))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader64); ok {
		return oh.MajorImageVersion, oh.MinorImageVersion
	}
	if oh, ok := f.OptionalHeader.(*pe.OptionalHeader32); ok {
		return oh.MajorImageVersion, oh.MinorImageVersion
	}
	t.Fatal("unknown OptionalHeader type")
	return 0, 0
}
