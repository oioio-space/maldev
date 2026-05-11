package packer_test

import (
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_RandomizeAll_DiffersFromDefaultOnAllFields
// verifies the Phase 2-E aggregator: setting RandomizeAll=true
// (and nothing else) produces an output where every Phase 2-A/B/C/D
// field differs from a default-pack of the same input + seed.
func TestPackBinary_RandomizeAll_DiffersFromDefaultOnAllFields(t *testing.T) {
	input := winhelloFixture(t)
	const seed int64 = 42

	defaultOut, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         seed,
	})
	if err != nil {
		t.Fatalf("default PackBinary: %v", err)
	}

	allOut, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         seed,
		RandomizeAll: true,
	})
	if err != nil {
		t.Fatalf("RandomizeAll PackBinary: %v", err)
	}

	if lastSectionName(t, allOut) == lastSectionName(t, defaultOut) {
		t.Errorf("RandomizeAll did not change stub section name: both = %q",
			lastSectionName(t, allOut))
	}
	if readPETimestamp(t, allOut) == readPETimestamp(t, defaultOut) {
		t.Errorf("RandomizeAll did not change TimeDateStamp: both = %d",
			readPETimestamp(t, allOut))
	}
	maj1, min1 := readPELinkerVersion(t, allOut)
	maj2, min2 := readPELinkerVersion(t, defaultOut)
	if maj1 == maj2 && min1 == min2 {
		t.Errorf("RandomizeAll did not change LinkerVersion: both = %d.%d", maj1, min1)
	}
	imaj1, imin1 := readPEImageVersion(t, allOut)
	imaj2, imin2 := readPEImageVersion(t, defaultOut)
	if imaj1 == imaj2 && imin1 == imin2 {
		t.Errorf("RandomizeAll did not change ImageVersion: both = %d.%d", imaj1, imin1)
	}

	// Phase 2-F-1: existing-section names must differ too. Compare
	// host sections (excluding the appended stub on both sides).
	allHost := hostSectionNames(t, allOut)
	defHost := hostSectionNames(t, defaultOut)
	identical := len(allHost) == len(defHost)
	for i := 0; identical && i < len(allHost); i++ {
		if allHost[i] != defHost[i] {
			identical = false
		}
	}
	if identical {
		t.Errorf("RandomizeAll did not rename existing sections: both = %v", allHost)
	}
}

// TestPackBinary_RandomizeAll_DeterministicGivenSeed confirms
// the reproducible-build property survives the aggregator.
func TestPackBinary_RandomizeAll_DeterministicGivenSeed(t *testing.T) {
	input := winhelloFixture(t)
	opts := packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         999,
		RandomizeAll: true,
	}
	a, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary A: %v", err)
	}
	b, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary B: %v", err)
	}
	if lastSectionName(t, a) != lastSectionName(t, b) ||
		readPETimestamp(t, a) != readPETimestamp(t, b) {
		t.Error("same seed produced non-reproducible output under RandomizeAll")
	}
}
