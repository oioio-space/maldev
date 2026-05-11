package stage1_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"golang.org/x/arch/x86/x86asm"
)

// stdPlan is the canonical transform.Plan used by most stub tests.
// StubRVA is placed well above TextRVA so PatchTextDisplacement produces
// a negative (but valid) displacement for the prologue ADD.
var stdPlan = transform.Plan{
	Format:      transform.FormatPE,
	TextRVA:     0x1000,
	TextSize:    0x100,
	OEPRVA:      0x1010,
	StubRVA:     0x2000,
	StubMaxSize: 4096,
}

// makeRounds builds n Round structures with predictable substitutions
// using a fixed seed so the test output is deterministic.
func makeRounds(n int) []poly.Round {
	rng := rand.New(rand.NewSource(42))
	regs := poly.NewRegPool(rng)
	out := make([]poly.Round, n)
	for i := 0; i < n; i++ {
		k, _ := regs.Take()
		bt, _ := regs.Take()
		s, _ := regs.Take()
		c, _ := regs.Take()
		out[i] = poly.Round{
			Key:     uint8(0x10 + i),
			Subst:   poly.XorSubsts[0], // canonical XOR
			KeyReg:  k, ByteReg: bt, SrcReg: s, CntReg: c,
		}
		regs.Release(k)
		regs.Release(bt)
		regs.Release(s)
		regs.Release(c)
	}
	return out
}

func TestEmitStub_BeginsWithCALL(t *testing.T) {
	rounds := makeRounds(3)

	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitStub(b, stdPlan, rounds, stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitStub: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("EmitStub produced 0 bytes")
	}
	// First instruction must be CALL (0xE8) — the CALL+POP+ADD PIC prologue.
	inst, err := x86asm.Decode(out, 64)
	if err != nil {
		t.Fatalf("Decode first instruction: %v", err)
	}
	if inst.Op != x86asm.CALL {
		t.Errorf("first instruction = %v, want CALL", inst.Op)
	}
}

func TestEmitStub_EndsWithJMP(t *testing.T) {
	rounds := makeRounds(1)

	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitStub(b, stdPlan, rounds, stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitStub: %v", err)
	}
	out, _ := b.Encode()

	// Walk all decodable instructions; the last decoded op must be JMP.
	off := 0
	var lastOp x86asm.Op
	for off < len(out) {
		inst, err := x86asm.Decode(out[off:], 64)
		if err != nil {
			break
		}
		lastOp = inst.Op
		off += inst.Len
		if off >= len(out)-1 {
			break
		}
	}
	if lastOp != x86asm.JMP {
		t.Errorf("last decoded instruction = %v, want JMP", lastOp)
	}
}

func TestEmitStub_RespectsRoundCount(t *testing.T) {
	for _, n := range []int{1, 3, 5} {
		b, err := amd64.New()
		if err != nil {
			t.Fatalf("amd64.New (n=%d): %v", n, err)
		}
		rounds := makeRounds(n)
		if err := stage1.EmitStub(b, stdPlan, rounds, stage1.EmitOptions{}); err != nil {
			t.Errorf("n=%d EmitStub: %v", n, err)
			continue
		}
		out, err := b.Encode()
		if err != nil {
			t.Errorf("n=%d Encode: %v", n, err)
			continue
		}
		if len(out) == 0 {
			t.Errorf("n=%d produced 0 bytes", n)
		}
	}
}

func TestEmitStub_RejectsZeroRounds(t *testing.T) {
	plan := transform.Plan{Format: transform.FormatPE}
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	err = stage1.EmitStub(b, plan, []poly.Round{}, stage1.EmitOptions{})
	if !errors.Is(err, stage1.ErrNoRounds) {
		t.Errorf("got %v, want ErrNoRounds", err)
	}
}

// TestEmitStub_AllSubsts verifies that EmitStub assembles cleanly for
// every substitution variant (XOR / SUB-neg / ADD-complement), confirming
// that none of the sub-emitters introduces an invalid instruction sequence.
func TestEmitStub_AllSubsts(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for substIdx, subst := range poly.XorSubsts {
		t.Run(string(rune('A'+substIdx)), func(t *testing.T) {
			regs := poly.NewRegPool(rng)
			k, _ := regs.Take()
			bt, _ := regs.Take()
			s, _ := regs.Take()
			c, _ := regs.Take()
			round := poly.Round{
				Key:     0x42,
				Subst:   subst,
				KeyReg:  k, ByteReg: bt, SrcReg: s, CntReg: c,
			}
			b, err := amd64.New()
			if err != nil {
				t.Fatalf("amd64.New: %v", err)
			}
			if err := stage1.EmitStub(b, stdPlan, []poly.Round{round}, stage1.EmitOptions{}); err != nil {
				t.Fatalf("EmitStub: %v", err)
			}
			out, err := b.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if len(out) == 0 {
				t.Fatal("Encode returned 0 bytes")
			}
		})
	}
}

// TestEmitStub_Compress_Default verifies that the zero-value EmitOptions
// (Compress=false) does NOT include any LZ4 inflate bytes. The first three
// bytes of the LZ4 decoder (49 89 C2 = MOV R10, RAX — the emit_entry
// initialisation) must be absent so the non-compress path is unchanged.
func TestEmitStub_Compress_Default(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitStub(b, stdPlan, makeRounds(1), stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitStub: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	// First three bytes of the LZ4 decoder: MOV R10, RAX (49 89 C2).
	// These must NOT appear when Compress=false.
	lz4Sig := []byte{0x49, 0x89, 0xC2}
	if bytes.Contains(out, lz4Sig) {
		t.Error("stub without Compress=true contains LZ4 decoder signature bytes (49 89 C2)")
	}
}

// TestEmitStub_Compress_AsmAssembles verifies that EmitOptions{Compress:true}
// assembles without error and that the emitted bytes contain both the LZ4
// register-setup sequence (MOV RAX, R15 = 4C 89 F8) and the opening bytes of
// the LZ4 block decoder (MOV R10, RAX = 49 89 C2) placed immediately after.
// It also confirms the stub does NOT end with RET (0xC3) followed by nothing —
// after the inline decoder the OEP epilogue JMP must follow.
func TestEmitStub_Compress_AsmAssembles(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	opts := stage1.EmitOptions{
		Compress:            true,
		SafetyMargin:        64,
		CompressedSize:      512,
		OriginalSize:        4096,
		ScratchDispFromText: 0x10000,
	}
	if err := stage1.EmitStub(b, stdPlan, makeRounds(1), opts); err != nil {
		t.Fatalf("EmitStub Compress=true: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// MOV RAX, R15 (4C 89 F8) opens the LZ4 register-setup. The scratch-
	// buffer dst (RBX = R15+disp) is set via LEA, then RCX = CompressedSize.
	if !bytes.Contains(out, []byte{0x4C, 0x89, 0xF8}) {
		t.Errorf("stub missing LZ4 setup MOV RAX,R15 (4C 89 F8)")
	}
	// CLD (FC) opens the post-inflate memcpy-back epilogue.
	if !bytes.Contains(out, []byte{0xFC}) {
		t.Errorf("stub missing memcpy-back CLD (0xFC)")
	}

	// First three bytes of the LZ4 decoder: emit_entry MOV R10,RAX = 49 89 C2.
	lz4Sig := []byte{0x49, 0x89, 0xC2}
	if !bytes.Contains(out, lz4Sig) {
		t.Errorf("stub missing LZ4 decoder signature (49 89 C2 = MOV R10,RAX)")
	}

	// The stub must NOT end with bare 0xC3 (standalone RET). The inline decoder
	// omits the terminal RET so execution falls through to the JMP-OEP epilogue.
	// The stub always ends with FF E7 (JMP R15) or FF D7 (JMP reg) — never C3.
	last := out[len(out)-1]
	if last == 0xC3 {
		t.Errorf("stub last byte = 0xC3 (RET): inline LZ4 decoder was NOT used — must use EmitLZ4InflateInline")
	}
}

// TestEmitLZ4InflateInline_NoRetByte verifies that EmitLZ4InflateInline emits
// exactly one fewer byte than EmitLZ4Inflate and that the omitted byte is 0xC3
// (the RET that terminates the standalone decoder).
func TestEmitLZ4InflateInline_NoRetByte(t *testing.T) {
	emitFull := func() []byte {
		t.Helper()
		b, err := amd64.New()
		if err != nil {
			t.Fatalf("amd64.New (full): %v", err)
		}
		if err := stage1.EmitLZ4Inflate(b); err != nil {
			t.Fatalf("EmitLZ4Inflate: %v", err)
		}
		out, err := b.Encode()
		if err != nil {
			t.Fatalf("Encode (full): %v", err)
		}
		return out
	}()

	emitInline := func() []byte {
		t.Helper()
		b, err := amd64.New()
		if err != nil {
			t.Fatalf("amd64.New (inline): %v", err)
		}
		if err := stage1.EmitLZ4InflateInline(b); err != nil {
			t.Fatalf("EmitLZ4InflateInline: %v", err)
		}
		out, err := b.Encode()
		if err != nil {
			t.Fatalf("Encode (inline): %v", err)
		}
		return out
	}()

	if len(emitInline) != len(emitFull)-1 {
		t.Errorf("inline size = %d, want full size - 1 = %d", len(emitInline), len(emitFull)-1)
	}
	if emitFull[len(emitFull)-1] != 0xC3 {
		t.Errorf("EmitLZ4Inflate last byte = %#x, want 0xC3 (RET)", emitFull[len(emitFull)-1])
	}
	// Inline bytes must be a prefix of the full bytes.
	if !bytes.Equal(emitInline, emitFull[:len(emitInline)]) {
		t.Error("EmitLZ4InflateInline bytes differ from EmitLZ4Inflate prefix")
	}
}

// TestEmitStub_Compress_RejectsZeroMargin verifies that Compress=true with
// any of CompressedSize, OriginalSize, ScratchDispFromText is zero returns an
// error — these would either loop indefinitely or skip the memmove preamble.
func TestEmitStub_Compress_RejectsZeroMargin(t *testing.T) {
	cases := []stage1.EmitOptions{
		{Compress: true, CompressedSize: 0, OriginalSize: 4096, ScratchDispFromText: 0x1000},
		{Compress: true, CompressedSize: 512, OriginalSize: 0, ScratchDispFromText: 0x1000},
		{Compress: true, CompressedSize: 512, OriginalSize: 4096, ScratchDispFromText: 0},
	}
	for _, opts := range cases {
		b, err := amd64.New()
		if err != nil {
			t.Fatalf("amd64.New: %v", err)
		}
		if err := stage1.EmitStub(b, stdPlan, makeRounds(1), opts); err == nil {
			t.Errorf("CompressedSize=%d OriginalSize=%d ScratchDispFromText=%d: expected error, got nil",
				opts.CompressedSize, opts.OriginalSize, opts.ScratchDispFromText)
		}
	}
}

// TestPatchTextDisplacement_HappyPath verifies that PatchTextDisplacement
// finds the sentinel 0xCAFEBABE in a hand-crafted byte slice and replaces
// it with the expected signed displacement.
func TestPatchTextDisplacement_HappyPath(t *testing.T) {
	plan := transform.Plan{
		TextRVA: 0x1000,
		StubRVA: 0x2000,
	}
	// Craft a real CALL+POP+ADD prologue so the patcher's
	// popOffset derivation (sentinel position − 5) lands on the
	// correct byte. The slice-5.5.x fix replaced a hardcoded
	// popOffset=5 with sentinelOff-5; the fixture must therefore
	// model the actual stub layout:
	//   E8 00 00 00 00   ; CALL .next   (5 B at offsets 0..4)
	//   41 5F            ; POP r15      (2 B at offsets 5..6)
	//   49 81 C7         ; ADD r15 prefix (3 B at offsets 7..9)
	//   <imm32 sentinel> ; 0xCAFEBABE  (4 B at offsets 10..13)
	stub := []byte{
		0xE8, 0x00, 0x00, 0x00, 0x00, // CALL .next
		0x41, 0x5F, // POP r15
		0x49, 0x81, 0xC7, // ADD r15, imm32
		0xBE, 0xBA, 0xFE, 0xCA, // sentinel imm32 (little-endian 0xCAFEBABE)
	}

	n, err := stage1.PatchTextDisplacement(stub, plan)
	if err != nil {
		t.Fatalf("PatchTextDisplacement: %v", err)
	}
	if n != 1 {
		t.Errorf("patches = %d, want 1", n)
	}

	// At runtime POP r15 lands its operand (the pushed return address)
	// at the byte right after CALL — stub offset 5. So
	// popAddr = StubRVA + 5; disp = TextRVA - popAddr.
	const popOffset = 5
	expectedDisp := int32(plan.TextRVA) - int32(plan.StubRVA+popOffset)
	const sentinelOff = 10
	got := int32(binary.LittleEndian.Uint32(stub[sentinelOff:]))
	if got != expectedDisp {
		t.Errorf("patched displacement = %d (0x%x), want %d (0x%x)",
			got, uint32(got), expectedDisp, uint32(expectedDisp))
	}
}

// TestPatchTextDisplacement_DLLPrologue — DLL-shaped stubs place
// the CALL+POP+ADD idiom AFTER a 24-byte DllMain prologue (push
// rbp / mov rbp,rsp / sub rsp,N / 4 spills). The sentinel lands
// at offset 24+10=34, NOT at offset 10 like the EXE stub. The
// slice-5.5.x derivation popOffset=sentinelOff-5 must handle
// both layouts.
//
// Pre-fix bug: hardcoded popOffset=5 produced an R15 24 B above
// textBase at runtime → kernel32!LoadLibrary AV crash on the
// first MOVB inside the flag check.
func TestPatchTextDisplacement_DLLPrologue(t *testing.T) {
	plan := transform.Plan{TextRVA: 0x1000, StubRVA: 0x6000}
	// 24 bytes of dummy prologue + 5 B CALL + 2 B POP + 3 B ADD prefix
	// + 4 B sentinel = 38 total. The actual prologue bytes don't matter
	// to the patcher (it locates by the sentinel), but the count does
	// — sentinelOff = 34 in this layout.
	prologue := make([]byte, 24)
	for i := range prologue {
		prologue[i] = 0x90 // NOPs
	}
	stub := append([]byte{}, prologue...)
	stub = append(stub,
		0xE8, 0x00, 0x00, 0x00, 0x00, // CALL .next
		0x41, 0x5F, // POP r15
		0x49, 0x81, 0xC7, // ADD r15, imm32
		0xBE, 0xBA, 0xFE, 0xCA, // sentinel imm32
	)

	n, err := stage1.PatchTextDisplacement(stub, plan)
	if err != nil {
		t.Fatalf("PatchTextDisplacement: %v", err)
	}
	if n != 1 {
		t.Errorf("patches = %d, want 1", n)
	}

	// popAddr at runtime = StubRVA + 29 (CALL at stub offset 24 ⇒ POP
	// at offset 29). disp = TextRVA − popAddr = 0x1000 − 0x602D = -0x502D.
	const sentinelOff = 34
	const popOffset = sentinelOff - 5 // 29
	expectedDisp := int32(plan.TextRVA) - int32(plan.StubRVA+popOffset)
	got := int32(binary.LittleEndian.Uint32(stub[sentinelOff:]))
	if got != expectedDisp {
		t.Errorf("patched displacement = %d (0x%x), want %d (0x%x)",
			got, uint32(got), expectedDisp, uint32(expectedDisp))
	}
}

// TestPatchTextDisplacement_MissingSentinel verifies the error path when
// the sentinel is absent.
func TestPatchTextDisplacement_MissingSentinel(t *testing.T) {
	plan := transform.Plan{TextRVA: 0x1000, StubRVA: 0x2000}
	stub := bytes.Repeat([]byte{0x90}, 32) // all NOPs
	_, err := stage1.PatchTextDisplacement(stub, plan)
	if err == nil {
		t.Fatal("expected error for missing sentinel, got nil")
	}
}

// TestPatchTextDisplacement_FullStub runs EmitStub, Encode, then
// PatchTextDisplacement and confirms exactly one patch was applied and
// the sentinel bytes are gone.
func TestPatchTextDisplacement_FullStub(t *testing.T) {
	plan := transform.Plan{
		Format:      transform.FormatPE,
		TextRVA:     0x1000,
		TextSize:    0x100,
		OEPRVA:      0x1020,
		StubRVA:     0x3000,
		StubMaxSize: 4096,
	}
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	if err := stage1.EmitStub(b, plan, makeRounds(2), stage1.EmitOptions{}); err != nil {
		t.Fatalf("EmitStub: %v", err)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	n, err := stage1.PatchTextDisplacement(out, plan)
	if err != nil {
		t.Fatalf("PatchTextDisplacement: %v", err)
	}
	if n != 1 {
		t.Errorf("patches = %d, want 1", n)
	}

	// Sentinel must no longer be present after patching.
	sentinel := []byte{0xBE, 0xBA, 0xFE, 0xCA}
	if bytes.Contains(out, sentinel) {
		t.Error("sentinel 0xCAFEBABE still present after patching")
	}
}
