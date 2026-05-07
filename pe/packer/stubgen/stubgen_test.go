package stubgen_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen"
)

// TestGenerate_ProducesParsablePE verifies that Generate emits a
// structurally valid PE32+ with exactly 2 sections (.text + .maldev).
func TestGenerate_ProducesParsablePE(t *testing.T) {
	inner := bytes.Repeat([]byte("the quick brown fox "), 100) // ~2 KB
	out, err := stubgen.Generate(stubgen.Options{
		Inner:  inner,
		Rounds: 3,
		Seed:   1,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected emitted PE: %v", err)
	}
	defer f.Close()

	if len(f.Sections) != 2 {
		t.Errorf("Sections = %d, want 2", len(f.Sections))
	}
	if f.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("Machine = %#x, want AMD64 (%#x)", f.FileHeader.Machine, pe.IMAGE_FILE_MACHINE_AMD64)
	}
}

// TestGenerate_RejectsOutOfRangeRounds ensures values outside [1,10]
// are rejected with ErrInvalidRounds.
func TestGenerate_RejectsOutOfRangeRounds(t *testing.T) {
	for _, r := range []int{0, -1, 11} {
		_, err := stubgen.Generate(stubgen.Options{Inner: []byte("x"), Rounds: r})
		if !errors.Is(err, stubgen.ErrInvalidRounds) {
			t.Errorf("rounds=%d: got %v, want ErrInvalidRounds", r, err)
		}
	}
}

// TestGenerate_PerPackUniqueness checks that different seeds produce
// meaningfully different output: overall Hamming distance ≥ 25% of the
// shorter output's length. Seeds drive different register allocations,
// substitution choices, and junk insertion, so the .text section bytes
// should diverge well beyond the 25% threshold.
func TestGenerate_PerPackUniqueness(t *testing.T) {
	inner := bytes.Repeat([]byte{0x42}, 1024)
	out1, err := stubgen.Generate(stubgen.Options{Inner: inner, Rounds: 3, Seed: 1})
	if err != nil {
		t.Fatalf("Generate seed=1: %v", err)
	}
	out2, err := stubgen.Generate(stubgen.Options{Inner: inner, Rounds: 3, Seed: 2})
	if err != nil {
		t.Fatalf("Generate seed=2: %v", err)
	}
	if bytes.Equal(out1, out2) {
		t.Fatal("two packs with different seeds produced identical output")
	}
	minLen := min(len(out1), len(out2))
	differing := 0
	for i := 0; i < minLen; i++ {
		if out1[i] != out2[i] {
			differing++
		}
	}
	if differing < minLen/4 {
		t.Errorf("Hamming distance %d/%d < 25%%; per-pack uniqueness too low", differing, minLen)
	}
}

// TestPatchStage2_RoundTrip verifies that a patched stage-2 binary still
// parses as a valid PE and contains the payload bytes verbatim in the
// appended trailer.
func TestPatchStage2_RoundTrip(t *testing.T) {
	stage2, err := stubgen.PickStage2Variant(0)
	if err != nil {
		t.Fatalf("PickStage2Variant: %v", err)
	}
	payload := []byte("hello payload")
	key := []byte("aes-gcm-key")
	patched, err := stubgen.PatchStage2(stage2, payload, key)
	if err != nil {
		t.Fatalf("PatchStage2: %v", err)
	}
	// The trailer is appended after the PE body; debug/pe should still
	// parse the headers cleanly because it reads from offset 0.
	f, err := pe.NewFile(bytes.NewReader(patched))
	if err != nil {
		t.Errorf("patched stage2 doesn't parse as PE: %v", err)
	} else {
		f.Close()
	}
	if !bytes.Contains(patched, payload) {
		t.Error("patched binary doesn't contain payload bytes verbatim")
	}
}

// TestPatchStage2_MissingSentinel ensures that a buffer lacking the
// sentinel is rejected with ErrStage2SentinelMissing.
func TestPatchStage2_MissingSentinel(t *testing.T) {
	noSentinel := bytes.Repeat([]byte{0x00}, 1024)
	_, err := stubgen.PatchStage2(noSentinel, []byte("p"), []byte("k"))
	if !errors.Is(err, stubgen.ErrStage2SentinelMissing) {
		t.Errorf("got %v, want ErrStage2SentinelMissing", err)
	}
}

// TestGenerate_RoundsAffectOutputSize checks that more rounds produce
// strictly more stage-1 asm: each additional decoder loop adds
// instructions, growing the .text section's VirtualSize monotonically.
// File size stays constant because PE file-alignment (0x200) swallows
// small asm differences, so we compare the .text VirtualSize directly.
func TestGenerate_RoundsAffectOutputSize(t *testing.T) {
	inner := bytes.Repeat([]byte{0xAA}, 256)
	out1, err := stubgen.Generate(stubgen.Options{Inner: inner, Rounds: 1, Seed: 1})
	if err != nil {
		t.Fatalf("Generate rounds=1: %v", err)
	}
	out5, err := stubgen.Generate(stubgen.Options{Inner: inner, Rounds: 5, Seed: 1})
	if err != nil {
		t.Fatalf("Generate rounds=5: %v", err)
	}
	textVirt := func(raw []byte) uint32 {
		f, err := pe.NewFile(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("debug/pe rejected PE: %v", err)
		}
		defer f.Close()
		if len(f.Sections) == 0 {
			t.Fatal("no sections")
		}
		return f.Sections[0].VirtualSize
	}
	v1 := textVirt(out1)
	v5 := textVirt(out5)
	if v5 <= v1 {
		t.Errorf(".text VirtualSize rounds=5 (%d) not > rounds=1 (%d); extra decoder loops must grow .text", v5, v1)
	}
}
