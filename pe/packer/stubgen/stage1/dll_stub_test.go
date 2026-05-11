package stage1_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// stdDLLPlan mirrors [stdPlan] but with IsDLL=true. Required by
// EmitDLLStub's guard.
var stdDLLPlan = transform.Plan{
	Format:      transform.FormatPE,
	TextRVA:     0x1000,
	TextSize:    0x100,
	OEPRVA:      0x1010,
	StubRVA:     0x2000,
	StubMaxSize: 4096,
	IsDLL:       true,
}

// TestEmitDLLStub_RejectsExePlan — guard against accidental
// routing of an EXE Plan through the DLL emitter.
func TestEmitDLLStub_RejectsExePlan(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	plan := stdDLLPlan
	plan.IsDLL = false
	err = stage1.EmitDLLStub(b, plan, makeRounds(1))
	if !errors.Is(err, stage1.ErrDLLStubPlanMissing) {
		t.Errorf("got %v, want ErrDLLStubPlanMissing", err)
	}
}

// TestEmitDLLStub_RejectsZeroRounds — same contract as EmitStub.
func TestEmitDLLStub_RejectsZeroRounds(t *testing.T) {
	b, _ := amd64.New()
	err := stage1.EmitDLLStub(b, stdDLLPlan, nil)
	if !errors.Is(err, stage1.ErrNoRounds) {
		t.Errorf("got %v, want ErrNoRounds", err)
	}
}

// TestEmitDLLStub_HasBothSentinels — the assembled bytes must
// contain exactly one prologueSentinel (text disp, shared with
// EmitStub) AND exactly one dllStubSentinel (the 8B orig-DllMain
// slot). PatchTextDisplacement + PatchDllMainSlot rewrite each
// exactly once.
func TestEmitDLLStub_HasBothSentinels(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitDLLStub(b, stdDLLPlan, makeRounds(2)); err != nil {
		t.Fatalf("EmitDLLStub: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// 0xCAFEBABE prologue sentinel — one occurrence.
	textSent := []byte{0xBE, 0xBA, 0xFE, 0xCA}
	if got := bytes.Count(out, textSent); got != 1 {
		t.Errorf("prologueSentinel count = %d, want 1", got)
	}

	// 0xDEADC0DEDEADBABE DllMain-slot sentinel — one occurrence.
	var slotSent [8]byte
	binary.LittleEndian.PutUint64(slotSent[:], 0xDEADC0DEDEADBABE)
	if got := bytes.Count(out, slotSent[:]); got != 1 {
		t.Errorf("dllStubSentinel count = %d, want 1", got)
	}
}

// TestEmitDLLStub_FitsInStubMaxSize — the canonical 3-round DLL
// stub plus trailing data must fit comfortably under the default
// 4 KiB StubMaxSize budget. Catches accidental bloat from the
// prologue/epilogue accounting.
func TestEmitDLLStub_FitsInStubMaxSize(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitDLLStub(b, stdDLLPlan, makeRounds(3)); err != nil {
		t.Fatalf("EmitDLLStub: %v", err)
	}
	out, _ := b.Encode()
	if uint32(len(out)) > stdDLLPlan.StubMaxSize {
		t.Errorf("DLL stub %d B exceeds StubMaxSize %d", len(out), stdDLLPlan.StubMaxSize)
	}
	// Empirical floor: prologue (≈40B) + CALL+POP+ADD (10B) + reason
	// check (8B) + flag check (12B) + 3 rounds (~50B each) + epilogue
	// (≈40B) + trailing data (9B) ≈ 220 B. Catch regressions that
	// blow past 1 KiB.
	if len(out) > 1024 {
		t.Errorf("DLL stub %d B unexpectedly large (>1 KiB)", len(out))
	}
}

// TestPatchDLLStubDisplacements_RewritesBothDisps — the disp
// sentinels (flag/slot) carry the imm32 placeholders we bake
// into the MOVZX/MOV operands; PatchDLLStubDisplacements rewrites
// them with the correct R15-relative offsets once the stub byte
// layout is finalised.
func TestPatchDLLStubDisplacements_RewritesBothDisps(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitDLLStub(b, stdDLLPlan, makeRounds(1)); err != nil {
		t.Fatalf("EmitDLLStub: %v", err)
	}
	out, _ := b.Encode()

	flagSent := []byte{0x01, 0x00, 0xFE, 0x7F}
	slotSent := []byte{0x02, 0x00, 0xFE, 0x7F}
	if !bytes.Contains(out, flagSent) || !bytes.Contains(out, slotSent) {
		t.Fatal("pre-patch: missing one or both disp sentinels")
	}

	n, err := stage1.PatchDLLStubDisplacements(out, stdDLLPlan)
	if err != nil {
		t.Fatalf("PatchDLLStubDisplacements: %v", err)
	}
	// Flag disp appears 2× (MOVZX load + MOVB store), slot disp 1× (tail-call MOV).
	if n != 3 {
		t.Errorf("patched %d disps, want 3 (2 flag + 1 slot)", n)
	}
	if bytes.Contains(out, flagSent) || bytes.Contains(out, slotSent) {
		t.Error("post-patch: disp sentinel still present (not replaced)")
	}
}

// TestPatchDllMainSlot_RewritesAbsoluteVA — replaces the 8B
// sentinel with imageBase + OEPRVA and verifies the patched
// little-endian bytes match.
func TestPatchDllMainSlot_RewritesAbsoluteVA(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitDLLStub(b, stdDLLPlan, makeRounds(1)); err != nil {
		t.Fatalf("EmitDLLStub: %v", err)
	}
	out, _ := b.Encode()

	const absVA uint64 = 0x180001010 // imageBase 0x180000000 + OEP 0x1010
	off, err := stage1.PatchDllMainSlot(out, absVA)
	if err != nil {
		t.Fatalf("PatchDllMainSlot: %v", err)
	}
	if off <= 0 || off+8 > len(out) {
		t.Errorf("slot offset %d out of stub bounds %d", off, len(out))
	}
	got := binary.LittleEndian.Uint64(out[off : off+8])
	if got != absVA {
		t.Errorf("slot bytes = %#x, want %#x", got, absVA)
	}
}

// TestPatchDllMainSlot_RejectsMissingSentinel — patching a buffer
// that doesn't contain the sentinel must fail rather than silently
// rewrite arbitrary bytes.
func TestPatchDllMainSlot_RejectsMissingSentinel(t *testing.T) {
	buf := []byte{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}
	_, err := stage1.PatchDllMainSlot(buf, 0x180001000)
	if !errors.Is(err, stage1.ErrDLLStubSentinelNotFound) {
		t.Errorf("got %v, want ErrDLLStubSentinelNotFound", err)
	}
}
