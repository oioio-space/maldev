package antivm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHypervisorVendorName_KnownSignatures locks the friendly-name
// map: every documented hypervisor signature must round-trip to its
// expected display string. This is the only test in the file that
// runs identically on amd64 and the non-amd64 stub builds — the map
// is shared.
func TestHypervisorVendorName_KnownSignatures(t *testing.T) {
	cases := []struct {
		sig  string
		want string
	}{
		{"VMwareVMware", "VMware"},
		{"KVMKVMKVM\x00\x00\x00", "KVM"},
		{"Microsoft Hv", "Hyper-V"},
		{"XenVMMXenVMM", "Xen"},
		{"TCGTCGTCGTCG", "QEMU"},
		{"VBoxVBoxVBox", "VirtualBox"},
		{"bhyve bhyve ", "bhyve"},
		{" lrpepyh vr", "Parallels"},
		{"prl hyperv  ", "Parallels"},
		{"ACRNACRNACRN", "ACRN"},
		{"QNXQVMBSQG  ", "QNX Hypervisor"},
	}
	// Divergence guard — fails when someone adds a vendor to the map
	// without extending this table (silent coverage drop) or vice
	// versa (orphan test row).
	assert.Len(t, hypervisorVendors, len(cases),
		"hypervisorVendors and test cases out of sync")
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, HypervisorVendorName(tc.sig))
		})
	}
}

// TestHypervisorVendorName_UnknownReturnsEmpty guards the
// no-match contract — operators rely on `name == ""` to distinguish
// "I have a signature but don't recognise it" from "no hypervisor".
func TestHypervisorVendorName_UnknownReturnsEmpty(t *testing.T) {
	assert.Equal(t, "", HypervisorVendorName(""))
	assert.Equal(t, "", HypervisorVendorName("AAAAAAAAAAAA"))
	assert.Equal(t, "", HypervisorVendorName("totally-bogus"))
}

// TestHypervisorPresent_ReturnsBool is a smoke test — the actual
// boolean depends on whether the test runs in a VM, so we only
// assert that the call returns without panicking. Behavioural
// coverage lives in the VM matrix harness.
func TestHypervisorPresent_ReturnsBool(t *testing.T) {
	got := HypervisorPresent()
	t.Logf("HypervisorPresent() = %v on this host", got)
	// No assertion — the value depends on whether we're in a VM.
}

// TestRDTSCDelta_NonPositiveSamplesReturnZero locks the input
// validation contract so a caller passing 0 or -1 doesn't panic
// or burn cycles.
func TestRDTSCDelta_NonPositiveSamplesReturnZero(t *testing.T) {
	assert.Zero(t, RDTSCDelta(0))
	assert.Zero(t, RDTSCDelta(-1))
}

// TestRDTSCDelta_ReturnsPositiveOnAmd64 smoke-tests the asm wrapper
// — every CPU returns a non-zero delta around CPUID. On non-amd64
// the stub returns 0 and we skip.
func TestRDTSCDelta_ReturnsPositiveOnAmd64(t *testing.T) {
	d := RDTSCDelta(5)
	if d == 0 {
		t.Skip("RDTSCDelta returned 0 — likely non-amd64 stub")
	}
	t.Logf("median CPUID-bracketed RDTSC delta: %d cycles", d)
}

// TestLikelyVirtualizedByTiming_ThresholdHonoured guards the
// threshold semantics. A threshold of math.MaxUint64 must always
// return false (no signal exceeds it); a threshold of 0 must
// always return true on hosts where RDTSCDelta is non-zero.
func TestLikelyVirtualizedByTiming_ThresholdHonoured(t *testing.T) {
	assert.False(t, LikelyVirtualizedByTiming(^uint64(0)),
		"max threshold must never trip")

	if RDTSCDelta(1) == 0 {
		t.Skip("non-amd64 stub — zero-threshold check is meaningless")
	}
	assert.True(t, LikelyVirtualizedByTiming(0),
		"zero threshold must trip whenever the cycle counter advances")
}

// TestHypervisor_ReportShape verifies the aggregator wires every
// signal through. Behavioural assertions (LikelyVM == true on a
// VM) live in the VM matrix harness; here we only check the
// report's invariants:
//
//   - VendorName is empty when VendorSig is empty
//   - LikelyVM is the OR of every positive signal
func TestHypervisor_ReportShape(t *testing.T) {
	r := Hypervisor()
	t.Logf("HypervisorReport = %+v", r)

	if r.VendorSig == "" {
		assert.Equal(t, "", r.VendorName,
			"VendorName must be empty when VendorSig is empty")
	}
	want := r.Present || r.VendorSig != "" || r.TimingDelta > DefaultRDTSCThreshold
	assert.Equal(t, want, r.LikelyVM,
		"LikelyVM must be the OR of all positive signals")
}

// TestHypervisor_StableAcrossCalls — repeated calls must return the
// same Present + VendorSig (TimingDelta jitters; we don't assert
// equality on it). Catches regressions where a future "improvement"
// caches state mutably.
func TestHypervisor_StableAcrossCalls(t *testing.T) {
	r1 := Hypervisor()
	r2 := Hypervisor()
	assert.Equal(t, r1.Present, r2.Present)
	assert.Equal(t, r1.VendorSig, r2.VendorSig)
	assert.Equal(t, r1.VendorName, r2.VendorName)
}

// TestHypervisorVendor_ConsistentWithPresent enforces the documented
// contract: HypervisorVendor returns "" iff HypervisorPresent is
// false. When present, the returned string is exactly 12 bytes (one
// register triple from CPUID.40000000h's EBX:ECX:EDX).
func TestHypervisorVendor_ConsistentWithPresent(t *testing.T) {
	present := HypervisorPresent()
	vendor := HypervisorVendor()

	if !present {
		assert.Equal(t, "", vendor, "HypervisorVendor must be empty when HypervisorPresent is false")
		return
	}
	assert.Len(t, vendor, 12, "HypervisorVendor must be exactly 12 bytes (CPUID.40000000h EBX:ECX:EDX)")

	if name := HypervisorVendorName(vendor); name != "" {
		t.Logf("Detected hypervisor vendor: %q (%s)", vendor, name)
	} else {
		t.Logf("Detected unknown vendor signature: %q (consider adding to hypervisorVendors map)", vendor)
	}
}
