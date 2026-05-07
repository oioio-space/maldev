package poly_test

import (
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
	bytes, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(bytes) == 0 {
		t.Error("density=1 produced 0 bytes, want > 0")
	}
}
