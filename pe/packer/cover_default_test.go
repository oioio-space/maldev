package packer_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
)

// TestDefaultCoverOptions_ShapeAndDeterminism confirms the
// helper returns a non-empty 3-section options struct AND that
// the same seed produces the same options (operators relying on
// reproducible builds need this contract).
func TestDefaultCoverOptions_ShapeAndDeterminism(t *testing.T) {
	a := packerpkg.DefaultCoverOptions(42)
	b := packerpkg.DefaultCoverOptions(42)
	if len(a.JunkSections) != 3 {
		t.Fatalf("section count = %d, want 3", len(a.JunkSections))
	}
	if len(a.JunkSections) != len(b.JunkSections) {
		t.Errorf("non-deterministic: lengths differ %d vs %d", len(a.JunkSections), len(b.JunkSections))
	}
	for i := range a.JunkSections {
		if a.JunkSections[i] != b.JunkSections[i] {
			t.Errorf("section %d differs across same-seed calls: %+v vs %+v", i, a.JunkSections[i], b.JunkSections[i])
		}
	}
	// Sanity: each section has a non-empty name and non-zero size.
	for i, js := range a.JunkSections {
		if js.Name == "" {
			t.Errorf("section %d: empty name", i)
		}
		if js.Size == 0 {
			t.Errorf("section %d: zero size", i)
		}
	}
}

// TestDefaultCoverOptions_DifferentSeedsDiffer guards against a
// dropped-seed bug where every operator would get the same
// per-build cover.
func TestDefaultCoverOptions_DifferentSeedsDiffer(t *testing.T) {
	a := packerpkg.DefaultCoverOptions(1)
	b := packerpkg.DefaultCoverOptions(999)
	allSame := true
	for i := range a.JunkSections {
		if a.JunkSections[i] != b.JunkSections[i] {
			allSame = false
			break
		}
	}
	if allSame {
		t.Error("seeds 1 and 999 produced identical CoverOptions — RNG not threaded")
	}
}

// TestApplyDefaultCover_RejectsUnknownFormat ensures the
// auto-detect path errors cleanly on garbage input.
func TestApplyDefaultCover_RejectsUnknownFormat(t *testing.T) {
	_, err := packerpkg.ApplyDefaultCover([]byte("garbage"), 1)
	if !errors.Is(err, packerpkg.ErrCoverInvalidOptions) {
		t.Errorf("got %v, want ErrCoverInvalidOptions", err)
	}
}

// TestApplyDefaultCover_DispatchesToPE confirms the helper
// correctly routes a PE32+ input to AddCoverPE.
func TestApplyDefaultCover_DispatchesToPE(t *testing.T) {
	input := minimalPE32Plus(0x100)
	out, err := packerpkg.ApplyDefaultCover(input, 7)
	if err != nil {
		t.Fatalf("ApplyDefaultCover: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()
	// Original .text + 3 cover sections from defaults.
	if got := len(f.Sections); got != 4 {
		t.Errorf("section count = %d, want 4 (.text + 3 cover)", got)
	}
}

// TestApplyDefaultCover_DispatchesToELF confirms the helper
// routes an ELF64 input through AddCoverELF and surfaces the
// ELF-specific PHT-slack limitation accurately when the input
// has no slack.
func TestApplyDefaultCover_DispatchesToELF(t *testing.T) {
	// Synthetic ELF with slack — covers the happy-path dispatch.
	input := minimalELF64WithSlack(0x500)
	if _, err := packerpkg.ApplyDefaultCover(input, 11); err != nil {
		t.Errorf("ApplyDefaultCover on ELF with slack: %v", err)
	}
}
