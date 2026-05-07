package poly_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
)

func TestRegPool_TakeReturnsAllGPRs(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	p := poly.NewRegPool(rng)
	if got := p.Available(); got != 14 {
		t.Fatalf("Available() = %d, want 14 (all GPRs minus RSP/RBP)", got)
	}
	seen := map[amd64.Reg]bool{}
	for i := 0; i < 14; i++ {
		r, err := p.Take()
		if err != nil {
			t.Fatalf("Take #%d: %v", i, err)
		}
		if seen[r] {
			t.Errorf("duplicate register %v at Take #%d", r, i)
		}
		seen[r] = true
	}
	if _, err := p.Take(); err == nil {
		t.Error("Take on exhausted pool: got nil err, want exhausted error")
	}
}

func TestRegPool_ReleaseReturnsToPool(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	p := poly.NewRegPool(rng)
	r, err := p.Take()
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got := p.Available(); got != 13 {
		t.Fatalf("Available after Take = %d, want 13", got)
	}
	p.Release(r)
	if got := p.Available(); got != 14 {
		t.Errorf("Available after Release = %d, want 14", got)
	}
}

func TestInsertJunk_DensityZeroEmitsNothing(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	rng := rand.New(rand.NewSource(3))
	regs := poly.NewRegPool(rng)
	if err := poly.InsertJunk(b, 0.0, 9, regs, rng); err != nil {
		t.Fatalf("InsertJunk: %v", err)
	}
	bytes, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(bytes) != 0 {
		t.Errorf("density=0 produced %d bytes, want 0", len(bytes))
	}
}

func TestInsertJunk_DensityOneEmitsSomething(t *testing.T) {
	b, err := amd64.New()
	if err != nil {
		t.Fatalf("amd64.New: %v", err)
	}
	rng := rand.New(rand.NewSource(4))
	regs := poly.NewRegPool(rng)
	if err := poly.InsertJunk(b, 1.0, 9, regs, rng); err != nil {
		t.Fatalf("InsertJunk: %v", err)
	}
	got, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(got) == 0 {
		t.Error("density=1 produced 0 bytes, want > 0")
	}
}

func TestEngine_EncodeDecodeRoundTrip(t *testing.T) {
	original := make([]byte, 4096)
	for i := range original {
		original[i] = byte(i ^ 0x5A)
	}

	for _, rounds := range []int{1, 3, 7, 10} {
		t.Run(fmt.Sprintf("rounds=%d", rounds), func(t *testing.T) {
			eng, err := poly.NewEngine(int64(rounds*42+7), rounds)
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			encoded, rds, err := eng.EncodePayload(original)
			if err != nil {
				t.Fatalf("EncodePayload: %v", err)
			}
			if len(encoded) != len(original) {
				t.Fatalf("encoded len %d, want %d", len(encoded), len(original))
			}
			// Reverse the rounds (outermost layer first) to recover original.
			// Use each round's Decode function — the Go-side mirror of the
			// runtime asm decoder — so this test catches encode/decode mismatches
			// regardless of which substitution variant was chosen.
			decoded := append([]byte(nil), encoded...)
			for i := rounds - 1; i >= 0; i-- {
				key := rds[i].Key
				for j := range decoded {
					decoded[j] = rds[i].Subst.Decode(decoded[j], key)
				}
			}
			if !bytes.Equal(decoded, original) {
				t.Errorf("round-trip mismatch (first 8 bytes: encoded=%x decoded=%x original=%x)",
					encoded[:8], decoded[:8], original[:8])
			}
		})
	}
}

func TestEngine_RejectsOutOfRangeRounds(t *testing.T) {
	for _, n := range []int{0, -1, 11, 100} {
		if _, err := poly.NewEngine(1, n); err == nil {
			t.Errorf("NewEngine rounds=%d: got nil err, want range error", n)
		}
	}
}

// TestEngine_RoundTripPerSubst explicitly forces each substitution variant and
// verifies that Encode followed by Decode recovers the original byte. This is
// the regression test for the bug where subNegate and addComplement had a
// hardcoded XOR encoder that did not invert the respective asm decoder.
func TestEngine_RoundTripPerSubst(t *testing.T) {
	data := []byte("hello world")
	key := uint8(0x42)
	for substIdx, subst := range poly.XorSubsts {
		t.Run(fmt.Sprintf("subst_%d", substIdx), func(t *testing.T) {
			encoded := make([]byte, len(data))
			for i, b := range data {
				encoded[i] = subst.Encode(b, key)
			}
			decoded := make([]byte, len(encoded))
			for i, b := range encoded {
				decoded[i] = subst.Decode(b, key)
			}
			if !bytes.Equal(decoded, data) {
				t.Errorf("subst %d round-trip failed: got %x, want %x", substIdx, decoded, data)
			}
		})
	}
}

func TestEngine_DifferentSeedsProduceDifferentOutput(t *testing.T) {
	original := []byte("the quick brown fox")
	e1, err := poly.NewEngine(1, 3)
	if err != nil {
		t.Fatalf("NewEngine seed=1: %v", err)
	}
	e2, err := poly.NewEngine(2, 3)
	if err != nil {
		t.Fatalf("NewEngine seed=2: %v", err)
	}
	enc1, _, err := e1.EncodePayload(original)
	if err != nil {
		t.Fatalf("EncodePayload seed=1: %v", err)
	}
	enc2, _, err := e2.EncodePayload(original)
	if err != nil {
		t.Fatalf("EncodePayload seed=2: %v", err)
	}
	if bytes.Equal(enc1, enc2) {
		t.Error("different seeds produced identical encoded output")
	}
}
