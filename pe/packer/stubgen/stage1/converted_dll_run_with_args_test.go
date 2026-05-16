package stage1_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
	x86asm "golang.org/x/arch/x86/x86asm"
)

func emitRunWithArgsEntry(t *testing.T) []byte {
	t.Helper()
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitConvertedDLLRunWithArgsEntry(b, stdConvertedDLLPlan, stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitConvertedDLLRunWithArgsEntry: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	return out
}

// TestEmitConvertedDLLRunWithArgsEntry_RejectsExePlan — guard
// against routing a plain-EXE or native-DLL plan through the
// RunWithArgs emitter; only converted-DLL plans carry the OEPRVA
// the spawn block computes off R15.
func TestEmitConvertedDLLRunWithArgsEntry_RejectsExePlan(t *testing.T) {
	b, _ := amd64.New()
	plan := stdConvertedDLLPlan
	plan.IsConvertedDLL = false
	err := stage1.EmitConvertedDLLRunWithArgsEntry(b, plan, stage1.EmitOptions{})
	if err == nil {
		t.Fatal("expected ErrConvertedDLLPlanMissing on non-converted plan")
	}
}

// TestEmitConvertedDLLRunWithArgsEntry_HasSentinelPrefix — the entry
// starts with the 8-byte INT3 sentinel that PatchConvertedDLLRunWithArgsEntry
// (slice 1.B.1.c.4) scans for to locate the entry RVA.
func TestEmitConvertedDLLRunWithArgsEntry_HasSentinelPrefix(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)
	if !bytes.HasPrefix(emitted, stage1.RunWithArgsEntrySentinel[:]) {
		t.Errorf("entry does not start with RunWithArgsEntrySentinel; first 8 B = % x", emitted[:8])
	}
}

// TestEmitConvertedDLLRunWithArgsEntry_HasRWAPrologueSentinel — the
// entry contains the RWA prologue sentinel 0xCAFEBABF so the matching
// patcher can rewrite the CALL+POP+ADD displacement.
func TestEmitConvertedDLLRunWithArgsEntry_HasRWAPrologueSentinel(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)
	sentinel := []byte{0xBF, 0xBA, 0xFE, 0xCA} // 0xCAFEBABF LE
	if !bytes.Contains(emitted, sentinel) {
		t.Errorf("entry missing prologueSentinelRWA 0xCAFEBABF")
	}
	// MUST NOT contain the DllMain prologue sentinel 0xCAFEBABE —
	// would collide with PatchTextDisplacement.
	dllMainSentinel := []byte{0xBE, 0xBA, 0xFE, 0xCA}
	if bytes.Contains(emitted, dllMainSentinel) {
		t.Errorf("entry leaked prologueSentinel 0xCAFEBABE — would collide with DllMain patcher")
	}
}

// TestEmitConvertedDLLRunWithArgsEntry_EndsWithLeaveRet — the entry
// terminates with leave (0xC9) + ret (0xC3). Catches any future
// epilogue refactor that drops the explicit ret.
func TestEmitConvertedDLLRunWithArgsEntry_EndsWithLeaveRet(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)
	if len(emitted) < 2 {
		t.Fatalf("entry only %d bytes — too short", len(emitted))
	}
	if emitted[len(emitted)-2] != 0xC9 || emitted[len(emitted)-1] != 0xC3 {
		t.Errorf("entry does not end with leave/ret; last 2 B = % x", emitted[len(emitted)-2:])
	}
}

// TestEmitConvertedDLLRunWithArgsEntry_AssemblesCleanly — every
// non-sentinel byte decodes to a valid instruction. The 8-byte
// INT3 sentinel prefix is skipped because x86asm.Decode treats
// each INT3 as a separate 1-byte instruction (it would decode
// fine but inflate the count) — we want to validate the actual
// emitted asm.
func TestEmitConvertedDLLRunWithArgsEntry_AssemblesCleanly(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)
	// Skip the 8-byte sentinel; decode the rest.
	off := len(stage1.RunWithArgsEntrySentinel)
	for off < len(emitted) {
		inst, err := x86asm.Decode(emitted[off:], 64)
		if err != nil {
			t.Fatalf("decode failed at off 0x%x: %v\nbytes: %x", off, err, emitted[off:])
		}
		off += inst.Len
	}
}

// TestEmitConvertedDLLRunWithArgsEntry_HasSpawnBlockMarkers — sanity-
// check that the spawn block was actually emitted inside the entry.
// We look for two distinctive byte sequences:
//   - GS-prefixed PEB load (65 48 8B 04 25 60 00 00 00) used by both
//     EmitResolveKernel32Export and EmitPEBCommandLinePatchRCX
//   - rep movsb (F3 A4) used by the PEB-patch memcpy
//
// The 8-byte sentinel guarantees nothing here can be a false-positive
// from accidental matches in INT3 padding.
func TestEmitConvertedDLLRunWithArgsEntry_HasSpawnBlockMarkers(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)
	gsLoadPEB := []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}
	if !bytes.Contains(emitted, gsLoadPEB) {
		t.Errorf("entry missing GS-PEB load — spawn block not wired")
	}
	repMovsb := []byte{0xF3, 0xA4}
	if !bytes.Contains(emitted, repMovsb) {
		t.Errorf("entry missing rep movsb — runtime PEB patch not wired")
	}
}

// TestPatchRunWithArgsTextDisplacement_RewritesSentinel — the patcher
// finds the RWA prologue sentinel and rewrites it with the correct
// displacement. popAddr-relative arithmetic mirrors PatchTextDisplacement.
func TestPatchRunWithArgsTextDisplacement_RewritesSentinel(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)

	const rwaSentinel uint32 = 0xCAFEBABF
	needle := binary.LittleEndian.AppendUint32(nil, rwaSentinel)
	if !bytes.Contains(emitted, needle) {
		t.Fatalf("RWA sentinel not present in emitted entry")
	}

	plan := transform.Plan{
		StubRVA: 0x4000,
		TextRVA: 0x1000,
	}
	n, err := stage1.PatchRunWithArgsTextDisplacement(emitted, plan)
	if err != nil {
		t.Fatalf("PatchRunWithArgsTextDisplacement: %v", err)
	}
	if n != 1 {
		t.Errorf("patched %d sentinels, want 1", n)
	}
	if bytes.Contains(emitted, needle) {
		t.Errorf("RWA sentinel still present after patch")
	}
}

// TestEmitConvertedDLLRunWithArgsEntry_ReturnsExitCode — the entry
// resolves WaitForSingleObject + GetExitCodeThread (3 CALL R13 sites
// total with the spawn block's CreateThread) and loads the DWORD exit
// code with `mov eax, [rbp-0x10]` (8B 45 F0) just before the restore
// loop. Catches regressions that strip the Wait/ExitCode promotion
// and revert the entry to returning a raw HANDLE.
func TestEmitConvertedDLLRunWithArgsEntry_ReturnsExitCode(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)

	callR13 := []byte{0x41, 0xFF, 0xD5}
	calls := bytes.Count(emitted, callR13)
	if calls != 3 {
		t.Errorf("expected 3 `call r13` sites (CreateThread+Wait+GetExitCode), got %d", calls)
	}

	movEaxExitCode := []byte{0x8B, 0x45, 0xF0}
	if !bytes.Contains(emitted, movEaxExitCode) {
		t.Errorf("entry missing `mov eax, [rbp-0x10]` — exit-code load not wired")
	}
}

// TestPatchConvertedDLLRunWithArgsEntry_LocatesAndNOPs — patcher
// must find the sentinel, return its offset, and overwrite all 8
// bytes with 0x90. A second call on the patched buffer must fail
// (sentinel gone).
func TestPatchConvertedDLLRunWithArgsEntry_LocatesAndNOPs(t *testing.T) {
	emitted := emitRunWithArgsEntry(t)

	off, err := stage1.PatchConvertedDLLRunWithArgsEntry(emitted)
	if err != nil {
		t.Fatalf("PatchConvertedDLLRunWithArgsEntry: %v", err)
	}
	// Sentinel sits at +0 in the entry-only encoding.
	if off != 0 {
		t.Errorf("offset = %d, want 0 (sentinel at start of entry-only emit)", off)
	}
	for i := 0; i < len(stage1.RunWithArgsEntrySentinel); i++ {
		if emitted[off+i] != 0x90 {
			t.Errorf("byte %d not NOPped: %#x", off+i, emitted[off+i])
		}
	}
	if _, err := stage1.PatchConvertedDLLRunWithArgsEntry(emitted); err == nil {
		t.Error("second patch on already-NOPped buffer should error (sentinel gone)")
	}
}

// TestEmitConvertedDLLRunWithArgsEntry_PinnedByteCount — full entry
// size invariant. Bump deliberately when the asm template changes
// (anti-debug, additional resolves in slice 1.B.1.c.3, etc).
func TestEmitConvertedDLLRunWithArgsEntry_PinnedByteCount(t *testing.T) {
	got := emitRunWithArgsEntry(t)
	const want = 912
	if len(got) != want {
		t.Errorf("entry %d B, want %d B (asm template drift)", len(got), want)
	}
}
