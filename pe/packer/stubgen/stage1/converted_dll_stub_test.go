package stage1_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"golang.org/x/arch/x86/x86asm"
)

// stdConvertedDLLPlan mirrors stdDLLPlan but with IsConvertedDLL=true
// + IsDLL=false (it represents an EXE that the operator asked to
// pack as a DLL).
var stdConvertedDLLPlan = transform.Plan{
	Format:         transform.FormatPE,
	TextRVA:        0x1000,
	TextSize:       0x100,
	OEPRVA:         0x1010,
	StubRVA:        0x2000,
	StubMaxSize:    4096,
	IsConvertedDLL: true,
}

// TestEmitConvertedDLLStub_RejectsExePlan — guard against routing
// a plain EXE plan through the converted-DLL emitter. The flag
// must be set explicitly to avoid silent wrong-stub emission.
func TestEmitConvertedDLLStub_RejectsExePlan(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	plan := stdConvertedDLLPlan
	plan.IsConvertedDLL = false
	err = stage1.EmitConvertedDLLStub(b, plan, makeRounds(1))
	if !errors.Is(err, stage1.ErrConvertedDLLPlanMissing) {
		t.Errorf("got %v, want ErrConvertedDLLPlanMissing", err)
	}
}

// TestEmitConvertedDLLStub_RejectsZeroRounds — same contract as
// the other stub emitters.
func TestEmitConvertedDLLStub_RejectsZeroRounds(t *testing.T) {
	b, _ := amd64.New()
	err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, nil)
	if !errors.Is(err, stage1.ErrNoRounds) {
		t.Errorf("got %v, want ErrNoRounds", err)
	}
}

// TestEmitConvertedDLLStub_AssemblesCleanly — the emitted asm
// must decode without errors through x86asm.
func TestEmitConvertedDLLStub_AssemblesCleanly(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(3)); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("emitter produced 0 bytes")
	}
	off := 0
	for off < len(out) {
		inst, err := x86asm.Decode(out[off:], 64)
		if err != nil {
			t.Fatalf("decode at offset %d: %v", off, err)
		}
		off += inst.Len
	}
}

// TestEmitConvertedDLLStub_HasFlagSentinel — the flag-disp sentinel
// must appear at least once (MOVZX load + MOVB store both reference
// it). PatchConvertedDLLStubDisplacements rewrites every occurrence.
func TestEmitConvertedDLLStub_HasFlagSentinel(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(2)); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()
	sent := []byte{0x01, 0x00, 0xFE, 0x7F} // flagDispSentinel = 0x7FFE0001 LE
	if got := bytes.Count(out, sent); got < 1 {
		t.Errorf("flag sentinel occurs %d times, want ≥ 1", got)
	}
}

// TestEmitConvertedDLLStub_NoSlotSentinel — the converted-DLL stub
// must NOT carry the 8-byte orig_dllmain slot sentinel that the
// native-DLL stub uses. Different trailing data layout.
func TestEmitConvertedDLLStub_NoSlotSentinel(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(2)); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()
	if bytes.Contains(out, transform.DLLStubSentinelBytes) {
		t.Error("converted-DLL stub leaked DLLStubSentinel (native-DLL trailing data)")
	}
}

// TestEmitConvertedDLLStub_PinnedByteCount — full stub size for 3
// SGN rounds is invariant once the asm template is fixed. Pinning
// the exact byte count catches accidental drift from the resolver
// (slice 5.2: 196 B) or any prologue/SGN/epilogue tweak — would
// otherwise hide under a loose budget window for 50%+ regressions.
//
// Measured 2026-05-11; bump deliberately if the asm changes.
// Reference for sizing other round-counts: 1 round = 390 B,
// 3 rounds = 465 B, 10 rounds = 741 B.
func TestEmitConvertedDLLStub_PinnedByteCount(t *testing.T) {
	const want = 465 // 3-round stub
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(3)); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()
	if len(out) != want {
		t.Errorf("converted-DLL stub %d B, want %d B (asm template drift)", len(out), want)
	}
	if uint32(len(out)) > stdConvertedDLLPlan.StubMaxSize {
		t.Errorf("converted-DLL stub %d B exceeds StubMaxSize %d", len(out), stdConvertedDLLPlan.StubMaxSize)
	}
}

// TestPatchConvertedDLLStubDisplacements_RewritesFlagDisp — the
// patcher rewrites every flag-disp sentinel occurrence with the
// correct R15-relative offset.
func TestPatchConvertedDLLStubDisplacements_RewritesFlagDisp(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(1)); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()

	flagSent := []byte{0x01, 0x00, 0xFE, 0x7F}
	preCount := bytes.Count(out, flagSent)
	if preCount < 1 {
		t.Fatal("pre-patch: no flag sentinel present")
	}

	n, err := stage1.PatchConvertedDLLStubDisplacements(out, stdConvertedDLLPlan)
	if err != nil {
		t.Fatalf("PatchConvertedDLLStubDisplacements: %v", err)
	}
	if n != preCount {
		t.Errorf("patched %d occurrences, want %d (every sentinel rewritten)", n, preCount)
	}
	if bytes.Contains(out, flagSent) {
		t.Error("post-patch: flag sentinel still present (not all rewritten)")
	}
	// The new bytes at the patched sites should be the actual flag
	// disp: (StubRVA + len(out) - 1) - TextRVA.
	wantDisp := uint32(int32(stdConvertedDLLPlan.StubRVA+uint32(len(out))-1) - int32(stdConvertedDLLPlan.TextRVA))
	var wantBytes [4]byte
	binary.LittleEndian.PutUint32(wantBytes[:], wantDisp)
	if !bytes.Contains(out, wantBytes[:]) {
		t.Errorf("post-patch: real disp %#x not found in stub", wantDisp)
	}
}
