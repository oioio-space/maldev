package packer

import (
	"bytes"
	mathrand "math/rand"
	"testing"
)

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
