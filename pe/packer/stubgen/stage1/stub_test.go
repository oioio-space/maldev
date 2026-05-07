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
	if err := stage1.EmitStub(b, stdPlan, rounds); err != nil {
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
	if err := stage1.EmitStub(b, stdPlan, rounds); err != nil {
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
		if err := stage1.EmitStub(b, stdPlan, rounds); err != nil {
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
	err = stage1.EmitStub(b, plan, []poly.Round{})
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
			if err := stage1.EmitStub(b, stdPlan, []poly.Round{round}); err != nil {
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

// TestPatchTextDisplacement_HappyPath verifies that PatchTextDisplacement
// finds the sentinel 0xCAFEBABE in a hand-crafted byte slice and replaces
// it with the expected signed displacement.
func TestPatchTextDisplacement_HappyPath(t *testing.T) {
	plan := transform.Plan{
		TextRVA: 0x1000,
		StubRVA: 0x2000,
	}
	// Craft stub bytes: 7-byte ADD R15, imm32 prefix then sentinel.
	// Real stub prefix: 49 81 C7 BE BA FE CA (ADD R15, 0xCAFEBABE).
	// Here we use a minimal buffer: just [prefix(3)] + [sentinel(4)].
	const prefixLen = 3 // 49 81 C7
	stub := make([]byte, prefixLen+4)
	stub[0] = 0x49
	stub[1] = 0x81
	stub[2] = 0xC7
	binary.LittleEndian.PutUint32(stub[prefixLen:], 0xCAFEBABE)

	n, err := stage1.PatchTextDisplacement(stub, plan)
	if err != nil {
		t.Fatalf("PatchTextDisplacement: %v", err)
	}
	if n != 1 {
		t.Errorf("patches = %d, want 1", n)
	}

	// Verify the patched displacement:
	// nextRIP = StubRVA + prefixLen + 4 = 0x2000 + 3 + 4 = 0x2007
	// disp = int32(0x1000) - int32(0x2007) = -0x1007
	expectedDisp := int32(plan.TextRVA) - int32(plan.StubRVA+prefixLen+4)
	got := int32(binary.LittleEndian.Uint32(stub[prefixLen:]))
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
	if err := stage1.EmitStub(b, plan, makeRounds(2)); err != nil {
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
