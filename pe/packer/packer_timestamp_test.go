package packer_test

import (
	"bytes"
	"debug/pe"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_DefaultTimestamp_PreservesInputStamp pins the
// backwards-compatible default behaviour: when the operator
// doesn't opt in, the COFF TimeDateStamp from the input PE
// survives unchanged.
func TestPackBinary_DefaultTimestamp_PreservesInputStamp(t *testing.T) {
	input := winhelloFixture(t)
	want := readPETimestamp(t, input)

	out, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	got := readPETimestamp(t, out)
	if got != want {
		t.Errorf("default-pack changed TimeDateStamp: input %d, output %d (regression — RandomizeTimestamp is opt-in)",
			want, got)
	}
}

// TestPackBinary_RandomizeTimestamp_Differs verifies the Phase
// 2-B opt-in: setting RandomizeTimestamp=true should produce a
// timestamp that differs from the input PE's, and differs again
// across seeds.
func TestPackBinary_RandomizeTimestamp_Differs(t *testing.T) {
	input := winhelloFixture(t)
	inputTS := readPETimestamp(t, input)

	out1, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:             packerpkg.FormatWindowsExe,
		Stage1Rounds:       3,
		Seed:               42,
		RandomizeTimestamp: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=42: %v", err)
	}
	out2, _, err := packerpkg.PackBinary(input, packerpkg.PackBinaryOptions{
		Format:             packerpkg.FormatWindowsExe,
		Stage1Rounds:       3,
		Seed:               1337,
		RandomizeTimestamp: true,
	})
	if err != nil {
		t.Fatalf("PackBinary seed=1337: %v", err)
	}

	ts1 := readPETimestamp(t, out1)
	ts2 := readPETimestamp(t, out2)

	if ts1 == inputTS {
		t.Errorf("seed=42 timestamp matches input %d — randomisation didn't fire", ts1)
	}
	if ts1 == ts2 {
		t.Errorf("seeds 42 and 1337 produced identical timestamps %d", ts1)
	}
}

// TestPackBinary_RandomizeTimestamp_DeterministicGivenSeed
// confirms the reproducible-build property: same seed → same
// timestamp across packs.
func TestPackBinary_RandomizeTimestamp_DeterministicGivenSeed(t *testing.T) {
	input := winhelloFixture(t)
	opts := packerpkg.PackBinaryOptions{
		Format:             packerpkg.FormatWindowsExe,
		Stage1Rounds:       3,
		Seed:               999,
		RandomizeTimestamp: true,
	}
	a, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary A: %v", err)
	}
	b, _, err := packerpkg.PackBinary(input, opts)
	if err != nil {
		t.Fatalf("PackBinary B: %v", err)
	}
	if readPETimestamp(t, a) != readPETimestamp(t, b) {
		t.Errorf("same seed produced different timestamps: %d vs %d",
			readPETimestamp(t, a), readPETimestamp(t, b))
	}
}

// readPETimestamp extracts the COFF File Header TimeDateStamp from
// a PE byte buffer via debug/pe (independent path from the
// transform helpers — exercises the wire format end-to-end).
func readPETimestamp(t *testing.T, peBytes []byte) uint32 {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(peBytes))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	return f.FileHeader.TimeDateStamp
}
