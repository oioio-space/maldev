package packer

import (
	"bytes"
	mathrand "math/rand"
	"testing"
)

// TestSplitSeedRngs_Independence verifies that the two rngs derived
// from a single operator seed produce DIFFERENT byte streams (the
// XOR-mask achieves stream separation) and that a zero seed returns
// (nil, nil) — the contract expected by the polymorphism callers.
func TestSplitSeedRngs_Independence(t *testing.T) {
	if b, a := splitSeedRngs(0); b != nil || a != nil {
		t.Errorf("seed=0 must return (nil,nil); got (%v,%v)", b, a)
	}

	bRng, aRng := splitSeedRngs(42)
	if bRng == nil || aRng == nil {
		t.Fatalf("non-zero seed must yield two rngs; got bRng=%v aRng=%v", bRng, aRng)
	}

	// Pull 32 bytes from each — if the XOR-mask didn't decorrelate
	// them they'd be byte-identical (both seeded from `seed`).
	bStream := make([]byte, 32)
	aStream := make([]byte, 32)
	for i := range bStream {
		bStream[i] = byte(bRng.Intn(256))
		aStream[i] = byte(aRng.Intn(256))
	}
	if bytes.Equal(bStream, aStream) {
		t.Errorf("bRng and aRng produced identical 32-byte streams — XOR-mask not decorrelating")
	}

	// Determinism: same seed → identical streams from the same slot.
	bRng2, _ := splitSeedRngs(42)
	for i := range bStream {
		if got := byte(bRng2.Intn(256)); got != bStream[i] {
			t.Errorf("bRng not deterministic at byte %d: %#x vs %#x", i, got, bStream[i])
			break
		}
	}
}

// TestBundleStub_V2Negate_SlotsBC_Polymorphism verifies that the
// rng-driven slots B and C produce DIFFERENT byte sequences across
// distinct seeds while remaining DETERMINISTIC for a given seed.
// The same-seed pair must be byte-identical (reproducible packing);
// the cross-seed pair must differ (per-pack polymorphism that yara
// hashes can't cluster).
func TestBundleStub_V2Negate_SlotsBC_Polymorphism(t *testing.T) {
	noJunk, _, err := bundleStubVendorAwareV2NegateRng(nil)
	if err != nil {
		t.Fatalf("V2N no-junk: %v", err)
	}

	withSeed := func(seed int64) []byte {
		rng := mathrand.New(mathrand.NewSource(seed))
		stub, _, err := bundleStubVendorAwareV2NegateRng(rng)
		if err != nil {
			t.Fatalf("V2N seed=%d: %v", seed, err)
		}
		return stub
	}

	a1 := withSeed(1)
	a2 := withSeed(1)
	b1 := withSeed(2)

	if !bytes.Equal(a1, a2) {
		t.Errorf("same seed produced different stubs (len %d vs %d) — non-deterministic", len(a1), len(a2))
	}
	if bytes.Equal(a1, b1) {
		t.Errorf("seed=1 and seed=2 produced identical stubs (%d B) — polymorphism slot is no-op", len(a1))
	}
	if bytes.Equal(a1, noJunk) {
		t.Errorf("seeded stub equals no-junk stub — slots B/C aren't firing")
	}
	if len(a1) <= len(noJunk) {
		t.Errorf("seeded stub (%d B) not bigger than no-junk (%d B) — slot emission missing", len(a1), len(noJunk))
	}
}

// TestBundleStub_V2NW_SlotsBC_Polymorphism mirrors the V2-Negate test
// for the Windows V2NW stub. Same invariants: determinism per seed,
// difference across seeds, growth vs no-junk baseline.
func TestBundleStub_V2NW_SlotsBC_Polymorphism(t *testing.T) {
	noJunk, _, err := bundleStubV2NegateWinBuildWindowsRng(nil)
	if err != nil {
		t.Fatalf("V2NW no-junk: %v", err)
	}

	withSeed := func(seed int64) []byte {
		rng := mathrand.New(mathrand.NewSource(seed))
		stub, _, err := bundleStubV2NegateWinBuildWindowsRng(rng)
		if err != nil {
			t.Fatalf("V2NW seed=%d: %v", seed, err)
		}
		return stub
	}

	a1 := withSeed(1)
	a2 := withSeed(1)
	b1 := withSeed(2)

	if !bytes.Equal(a1, a2) {
		t.Errorf("V2NW same seed produced different stubs — non-deterministic")
	}
	if bytes.Equal(a1, b1) {
		t.Errorf("V2NW seed=1 and seed=2 produced identical stubs — polymorphism slot is no-op")
	}
	if bytes.Equal(a1, noJunk) {
		t.Errorf("V2NW seeded stub equals no-junk stub — slots B/C aren't firing")
	}
	if len(a1) <= len(noJunk) {
		t.Errorf("V2NW seeded stub (%d B) not bigger than no-junk (%d B)", len(a1), len(noJunk))
	}
}
