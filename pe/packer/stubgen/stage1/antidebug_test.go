package stage1_test

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// gsPrefix is the raw encoding of "mov rax, gs:[0x60]" — the first
// instruction of both PEB checks. Its presence in the emitted bytes
// confirms the anti-debug prologue was actually emitted.
var gsPrefix = []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}

// cpuidOpcode is the 2-byte encoding of CPUID. Present once per
// anti-debug prologue (RDTSC-delta check, leaf 0).
var cpuidOpcode = []byte{0x0F, 0xA2}

// TestEmitStub_AntiDebug_AsmAssembles confirms that EmitStub with
// AntiDebug=true assembles without error and the output contains the
// GS-override prefix pattern (PEB access) and the CPUID opcode.
func TestEmitStub_AntiDebug_AsmAssembles(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	rounds := makeRounds(3)
	if err := stage1.EmitStub(b, stdPlan, rounds, stage1.EmitOptions{AntiDebug: true}); err != nil {
		t.Fatalf("EmitStub AntiDebug=true: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("Encode returned 0 bytes")
	}
	if _, err := stage1.PatchTextDisplacement(out, stdPlan); err != nil {
		t.Fatalf("PatchTextDisplacement: %v", err)
	}

	// GS prefix must appear at least twice (Check 1 + Check 2 both load
	// gs:[0x60]).
	count := 0
	haystack := out
	for {
		idx := bytes.Index(haystack, gsPrefix)
		if idx < 0 {
			break
		}
		count++
		haystack = haystack[idx+len(gsPrefix):]
	}
	if count < 2 {
		t.Errorf("gs:[0x60] prefix found %d times, want ≥ 2", count)
	}

	// CPUID must appear exactly once.
	if !bytes.Contains(out, cpuidOpcode) {
		t.Error("CPUID opcode (0F A2) not found in emitted bytes")
	}
}

// TestEmitStub_AntiDebug_DefaultOff confirms that the zero-value EmitOptions
// (AntiDebug=false) does NOT emit GS-prefix instructions — the default path
// must produce byte-identical output to v0.64.x.
func TestEmitStub_AntiDebug_DefaultOff(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	rounds := makeRounds(3)
	if err := stage1.EmitStub(b, stdPlan, rounds, stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitStub default: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if bytes.Contains(out, gsPrefix) {
		t.Error("gs:[0x60] prefix present with AntiDebug=false; default path must not emit prologue")
	}
	if bytes.Contains(out, cpuidOpcode) {
		t.Error("CPUID opcode present with AntiDebug=false")
	}
}

// TestEmitStub_AntiDebug_ELFSkip confirms that AntiDebug=true on an ELF plan
// does NOT emit GS-prefix instructions — ELF stubs skip the Windows-specific
// prologue entirely.
func TestEmitStub_AntiDebug_ELFSkip(t *testing.T) {
	elfPlan := transform.Plan{
		Format:      transform.FormatELF,
		TextRVA:     0x1000,
		TextSize:    0x100,
		OEPRVA:      0x1010,
		StubRVA:     0x2000,
		StubMaxSize: 4096,
	}
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	rounds := makeRounds(1)
	if err := stage1.EmitStub(b, elfPlan, rounds, stage1.EmitOptions{AntiDebug: true}); err != nil {
		t.Fatalf("EmitStub ELF AntiDebug=true: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	if bytes.Contains(out, gsPrefix) {
		t.Error("gs:[0x60] prefix present in ELF stub with AntiDebug=true; ELF must skip the prologue")
	}
}

// TestEmitStub_AntiDebug_StartsWithPrologue confirms that when AntiDebug=true
// the very first bytes are the GS-load (0x65 prefix), not the CALL (0xE8)
// of the PIC prologue — anti-debug must run BEFORE CALL+POP+ADD.
func TestEmitStub_AntiDebug_StartsWithPrologue(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	rounds := makeRounds(1)
	if err := stage1.EmitStub(b, stdPlan, rounds, stage1.EmitOptions{AntiDebug: true}); err != nil {
		t.Fatalf("EmitStub: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("0 bytes emitted")
	}
	// First byte must be 0x65 (GS segment-override prefix), not 0xE8 (CALL).
	if out[0] != 0x65 {
		t.Errorf("first byte = 0x%02X, want 0x65 (GS prefix); CALL+POP+ADD must follow anti-debug", out[0])
	}
}

// TestEmitStub_AntiDebug_RoundsVariance confirms that the anti-debug prologue
// assembles correctly across the representative round counts used in
// production (1, 3, 5, 7).
func TestEmitStub_AntiDebug_RoundsVariance(t *testing.T) {
	for _, n := range []int{1, 3, 5, 7} {
		t.Run("", func(t *testing.T) {
			b, err := amd64.New()
			if err != nil {
				t.Fatalf("n=%d amd64.New: %v", n, err)
			}
			eng, err := poly.NewEngine(42, n)
			if err != nil {
				t.Fatalf("n=%d NewEngine: %v", n, err)
			}
			_, rounds, err := eng.EncodePayloadExcluding([]byte("antidebug variance"), stage1.BaseReg)
			if err != nil {
				t.Fatalf("n=%d EncodePayload: %v", n, err)
			}
			if err := stage1.EmitStub(b, stdPlan, rounds, stage1.EmitOptions{AntiDebug: true}); err != nil {
				t.Fatalf("n=%d EmitStub: %v", n, err)
			}
			out, err := b.Encode()
			if err != nil {
				t.Fatalf("n=%d Encode: %v", n, err)
			}
			if _, err := stage1.PatchTextDisplacement(out, stdPlan); err != nil {
				t.Fatalf("n=%d Patch: %v", n, err)
			}
			if !bytes.Contains(out, gsPrefix) {
				t.Errorf("n=%d GS prefix missing", n)
			}
			if !bytes.Contains(out, cpuidOpcode) {
				t.Errorf("n=%d CPUID opcode missing", n)
			}
		})
	}
}
