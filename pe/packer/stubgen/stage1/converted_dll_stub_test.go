package stage1_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/encode"
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
	err = stage1.EmitConvertedDLLStub(b, plan, makeRounds(1), stage1.EmitOptions{})
	if !errors.Is(err, stage1.ErrConvertedDLLPlanMissing) {
		t.Errorf("got %v, want ErrConvertedDLLPlanMissing", err)
	}
}

// TestEmitConvertedDLLStub_RejectsZeroRounds — same contract as
// the other stub emitters.
func TestEmitConvertedDLLStub_RejectsZeroRounds(t *testing.T) {
	b, _ := amd64.New()
	err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, nil, stage1.EmitOptions{})
	if !errors.Is(err, stage1.ErrNoRounds) {
		t.Errorf("got %v, want ErrNoRounds", err)
	}
}

// TestEmitConvertedDLLStub_AssemblesCleanly — the emitted asm
// must decode without errors through x86asm.
func TestEmitConvertedDLLStub_AssemblesCleanly(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(3), stage1.EmitOptions{}); err != nil {
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
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(2), stage1.EmitOptions{}); err != nil {
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
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(2), stage1.EmitOptions{}); err != nil {
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
// Measured 2026-05-12; bumped by +44 B (slice 5.5.y) when the
// prologue grew to spill the full Win64 callee-saved GPR set
// (RBX, RDI, RSI, R12, R13, R14). Bump deliberately if the asm
// changes. Reference for sizing other round-counts: the +44 B
// delta applies uniformly across round counts.
func TestEmitConvertedDLLStub_PinnedByteCount(t *testing.T) {
	const want = 509 // 3-round stub
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(3), stage1.EmitOptions{}); err != nil {
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

// TestEmitConvertedDLLStub_RunWithArgs_EmbedsEntry — when
// EmitOptions.RunWithArgs=true the encoded stub contains the
// RunWithArgs entry block. PatchConvertedDLLRunWithArgsEntry must
// locate the sentinel at a non-zero offset (DllMain body precedes
// it), NOP it, and the entry must end before the trailing flag byte.
func TestEmitConvertedDLLStub_RunWithArgs_EmbedsEntry(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(3), stage1.EmitOptions{RunWithArgs: true}); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()

	off, err := stage1.PatchConvertedDLLRunWithArgsEntry(out)
	if err != nil {
		t.Fatalf("PatchConvertedDLLRunWithArgsEntry: %v", err)
	}
	if off == 0 {
		t.Errorf("entry sentinel at offset 0 — DllMain body should precede it")
	}
	if off >= len(out)-stage1.ConvertedDLLStubFlagByteOffsetFromEnd {
		t.Errorf("entry offset %d overlaps trailing flag byte at %d", off, len(out)-stage1.ConvertedDLLStubFlagByteOffsetFromEnd)
	}
	for i := 0; i < 8; i++ {
		if out[off+i] != 0x90 {
			t.Errorf("sentinel byte %d not NOPped: %#x", off+i, out[off+i])
		}
	}
}

// TestEmitConvertedDLLStub_AntiDebug_PrependsCheck — when AntiDebug=true
// the converted-DLL stub must start with the GS-prefixed PEB load
// (0x65 0x48 0x8B ... 0x60) that opens emitAntiDebugWindowsPE. Slice 5.6.
func TestEmitConvertedDLLStub_AntiDebug_PrependsCheck(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(2), stage1.EmitOptions{AntiDebug: true}); err != nil {
		t.Fatalf("EmitConvertedDLLStub AntiDebug=true: %v", err)
	}
	out, _ := b.Encode()
	if !bytes.HasPrefix(out, stage1.GSLoadPEBBytes[:]) {
		t.Errorf("AntiDebug=true stub does not start with GSLoadPEB; first 8 B = % x", out[:8])
	}
}

// TestEmitConvertedDLLStub_AntiDebug_DefaultOff — zero-value EmitOptions
// (AntiDebug=false) must NOT emit the GS-prefix at offset 0. Slice 5.6.
func TestEmitConvertedDLLStub_AntiDebug_DefaultOff(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(2), stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitConvertedDLLStub default: %v", err)
	}
	out, _ := b.Encode()
	if bytes.HasPrefix(out, stage1.GSLoadPEBBytes[:]) {
		t.Error("AntiDebug=false stub starts with GS-prefix load — antidebug leaked into default path")
	}
}

// TestPatchConvertedDLLStubDisplacements_RewritesFlagDisp — the
// patcher rewrites every flag-disp sentinel occurrence with the
// correct R15-relative offset.
func TestPatchConvertedDLLStubDisplacements_RewritesFlagDisp(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(1), stage1.EmitOptions{}); err != nil {
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

// TestEmitConvertedDLLStub_DefaultArgs_AppendsBuffer — DefaultArgs
// non-empty must (a) embed the PEB-patch sentinel (0xCAFEDADE) once
// in the asm, and (b) append the UTF-16LE-encoded args + 2B NUL
// terminator to the trailing data, BEFORE the 1B decrypted_flag.
// Layout is asserted because PatchPEBCommandLineDisp consumers rely
// on it.
func TestEmitConvertedDLLStub_DefaultArgs_AppendsBuffer(t *testing.T) {
	const args = "AB" // 2 wchars → 4 bytes UTF-16LE → 2 NUL → +1 flag = 7 trailing
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(1), stage1.EmitOptions{
		DefaultArgs: args,
	}); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()

	pebSentinel := []byte{0xDE, 0xDA, 0xFE, 0xCA} // 0xCAFEDADE LE
	if got := bytes.Count(out, pebSentinel); got != 1 {
		t.Errorf("PEB-patch sentinel count = %d, want 1", got)
	}

	// Layout: ...[A 0 B 0 0 0 flag] — 4+2+1 = 7 trailing bytes.
	wantTrail := []byte{'A', 0x00, 'B', 0x00, 0x00, 0x00, 0x00}
	if !bytes.HasSuffix(out, wantTrail) {
		t.Errorf("trailing bytes = % x, want suffix % x", out[len(out)-7:], wantTrail)
	}

	// Flag byte still at offset stub_size-1 (existing contract preserved).
	if out[len(out)-1] != 0x00 {
		t.Errorf("flag byte (offset -1) = %#x, want 0x00", out[len(out)-1])
	}
}

// TestEmitConvertedDLLStub_DefaultArgs_DisabledByDefault — empty
// DefaultArgs must NOT emit the PEB-patch sentinel and trailing
// data must remain a single flag byte. Regression guard for the
// gated path.
func TestEmitConvertedDLLStub_DefaultArgs_DisabledByDefault(t *testing.T) {
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(1), stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()

	pebSentinel := []byte{0xDE, 0xDA, 0xFE, 0xCA}
	if bytes.Contains(out, pebSentinel) {
		t.Error("PEB-patch sentinel leaked when DefaultArgs is empty")
	}
}

// TestPatchPEBCommandLineDisp_RewritesFromConvertedStub — chains
// EmitConvertedDLLStub(DefaultArgs=...) with PatchPEBCommandLineDisp
// using the offset returned by ConvertedDLLStubArgsBufferOffsetFromEnd.
// Sentinel must be gone and the computed disp must appear in its place.
func TestPatchPEBCommandLineDisp_RewritesFromConvertedStub(t *testing.T) {
	const args = "X"
	b, _ := amd64.New()
	if err := stage1.EmitConvertedDLLStub(b, stdConvertedDLLPlan, makeRounds(1), stage1.EmitOptions{
		DefaultArgs: args,
	}); err != nil {
		t.Fatalf("EmitConvertedDLLStub: %v", err)
	}
	out, _ := b.Encode()

	offFromEnd := stage1.ConvertedDLLStubArgsBufferOffsetFromEnd(len(encode.ToUTF16LE(args)))
	argsBufferOff := uint32(len(out) - offFromEnd)

	n, err := stage1.PatchPEBCommandLineDisp(out, stdConvertedDLLPlan.StubRVA, stdConvertedDLLPlan.TextRVA, argsBufferOff)
	if err != nil {
		t.Fatalf("PatchPEBCommandLineDisp: %v", err)
	}
	if n != 1 {
		t.Errorf("patched %d sentinels, want 1", n)
	}
	pebSentinel := []byte{0xDE, 0xDA, 0xFE, 0xCA}
	if bytes.Contains(out, pebSentinel) {
		t.Error("PEB-patch sentinel still present after patch")
	}
	wantDisp := uint32(int32(stdConvertedDLLPlan.StubRVA+argsBufferOff) - int32(stdConvertedDLLPlan.TextRVA))
	var wantBytes [4]byte
	binary.LittleEndian.PutUint32(wantBytes[:], wantDisp)
	if !bytes.Contains(out, wantBytes[:]) {
		t.Errorf("computed disp %#x not present in patched stub", wantDisp)
	}
}
