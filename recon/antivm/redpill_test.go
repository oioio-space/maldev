package antivm_test

import (
	"runtime"
	"testing"

	"github.com/oioio-space/maldev/recon/antivm"
)

// TestSIDT_AMD64ReturnsNonZero verifies SIDT on amd64 returns a
// non-zero IDT base — every running x86-64 host has an IDT, so
// zero is a guaranteed-wrong reading. On non-amd64 the stub
// returns 0/0 and the test skips.
func TestSIDT_AMD64ReturnsNonZero(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64-only")
	}
	base, _ := antivm.SIDT()
	if base == 0 {
		t.Error("SIDT base = 0; expected non-zero on a running host")
	}
}

// TestSGDT_AMD64ReturnsNonZero mirrors TestSIDT for SGDT.
func TestSGDT_AMD64ReturnsNonZero(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64-only")
	}
	base, _ := antivm.SGDT()
	if base == 0 {
		t.Error("SGDT base = 0; expected non-zero on a running host")
	}
}

// TestSLDT_AMD64ReturnsValue confirms SLDT executes without
// crashing — the value itself is allowed to be zero on modern
// kernels, so the assertion is just "the call returned".
func TestSLDT_AMD64ReturnsValue(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64-only")
	}
	_ = antivm.SLDT()
}

// TestProbe_ReportShape confirms the aggregated report fills its
// numeric fields on amd64. The LikelyVM flag is environment-
// dependent (bare-metal CI host vs the libvirt VM the dev box
// uses): the test asserts the flag is consistent with the
// individual signals, not its absolute value.
func TestProbe_ReportShape(t *testing.T) {
	r := antivm.Probe()
	if runtime.GOARCH == "amd64" {
		if r.IDTBase == 0 {
			t.Error("Probe: IDTBase = 0 on amd64")
		}
		if r.GDTBase == 0 {
			t.Error("Probe: GDTBase = 0 on amd64")
		}
	}
	wantLikely := r.IDTSuspect || r.GDTSuspect || r.LDTSuspect
	if r.LikelyVM != wantLikely {
		t.Errorf("LikelyVM = %v, want %v (OR of IDTSuspect=%v GDTSuspect=%v LDTSuspect=%v)",
			r.LikelyVM, wantLikely, r.IDTSuspect, r.GDTSuspect, r.LDTSuspect)
	}
}

// TestProbe_StableAcrossCalls confirms two consecutive Probe
// calls return identical IDT/GDT bases — the OS does not relocate
// these tables at runtime, so any drift would indicate a bug in
// the asm wrappers.
func TestProbe_StableAcrossCalls(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("amd64-only")
	}
	a := antivm.Probe()
	b := antivm.Probe()
	if a.IDTBase != b.IDTBase {
		t.Errorf("IDTBase drift: %#x vs %#x", a.IDTBase, b.IDTBase)
	}
	if a.GDTBase != b.GDTBase {
		t.Errorf("GDTBase drift: %#x vs %#x", a.GDTBase, b.GDTBase)
	}
}
