package stage1_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// TestEmit_AssemblesCleanlyForAllSubsts verifies that Emit produces
// well-formed machine bytes for each substitution variant (XOR /
// SUB-neg / ADD-complement). We don't execute the bytes here — that
// lives in the E2E test in Task 9. This test just confirms that
// golang-asm accepts the emitted instruction sequence for every
// substitution the engine can pick.
func TestEmit_AssemblesCleanlyForAllSubsts(t *testing.T) {
	for substIdx, subst := range poly.XorSubsts {
		t.Run(string(rune('A'+substIdx)), func(t *testing.T) {
			b, err := amd64.New()
			if err != nil {
				t.Fatalf("amd64.New: %v", err)
			}
			// Declare the payload label so the LEA has a target to resolve.
			_ = b.Label("payload")
			r := poly.Round{
				Key:     0x42,
				Subst:   subst,
				KeyReg:  amd64.RAX,
				ByteReg: amd64.RBX,
				SrcReg:  amd64.RCX,
				CntReg:  amd64.RDX,
			}
			if err := stage1.Emit(b, r, "loop_test", "payload", 16); err != nil {
				t.Fatalf("Emit: %v", err)
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

// TestEmit_NoTwoRoundsClashOnLabels checks that two rounds emitted
// back-to-back with distinct loopLabels assemble cleanly.  A label
// collision inside golang-asm surfaces as a panic-wrapped error in
// Encode; this test guards that regression.
func TestEmit_NoTwoRoundsClashOnLabels(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	_ = b.Label("payload")
	rng := rand.New(rand.NewSource(1))
	regs := poly.NewRegPool(rng)
	for i := 0; i < 2; i++ {
		k, _ := regs.Take()
		bt, _ := regs.Take()
		s, _ := regs.Take()
		c, _ := regs.Take()
		r := poly.Round{
			Key:     uint8(0x10 + i),
			Subst:   poly.XorSubsts[0],
			KeyReg:  k,
			ByteReg: bt,
			SrcReg:  s,
			CntReg:  c,
		}
		loopLabel := fmt.Sprintf("loop_%d", i)
		if err := stage1.Emit(b, r, loopLabel, "payload", 8); err != nil {
			t.Fatalf("round %d Emit: %v", i, err)
		}
		regs.Release(k)
		regs.Release(bt)
		regs.Release(s)
		regs.Release(c)
	}
	out, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("Encode returned 0 bytes")
	}
}

// goSideDecode is the Go reference decoder: it mirrors the asm loop's
// semantics exactly, applying each round's Subst.Decode in reverse
// order (outermost layer first, innermost last).  Using Subst.Decode
// rather than a hardcoded XOR keeps this in sync with each variant's
// algebraic inverse regardless of which substitution the engine chose.
func goSideDecode(encoded []byte, rounds []poly.Round) []byte {
	out := append([]byte(nil), encoded...)
	for i := len(rounds) - 1; i >= 0; i-- {
		for j := range out {
			out[j] = rounds[i].Subst.Decode(out[j], rounds[i].Key)
		}
	}
	return out
}

// TestGoSideDecode_RoundTrip sanity-checks the reference decoder
// against the engine's EncodePayload. Redundant with poly tests but
// cheap insurance against drift between the stage1 reference path and
// the engine's encode logic.
func TestGoSideDecode_RoundTrip(t *testing.T) {
	original := []byte("hello stage1 reference decoder")
	eng, err := poly.NewEngine(42, 5)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	enc, rds, err := eng.EncodePayload(original)
	if err != nil {
		t.Fatalf("EncodePayload: %v", err)
	}
	dec := goSideDecode(enc, rds)
	if !bytes.Equal(dec, original) {
		t.Errorf("round-trip mismatch")
	}
}
