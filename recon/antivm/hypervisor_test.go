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
		{"TCGTCGTCGTCG", "QEMU/TCG"},
		{"VBoxVBoxVBox", "VirtualBox"},
		{"bhyve bhyve ", "bhyve"},
		{" lrpepyh vr", "Parallels"},
		{"prl hyperv  ", "Parallels"},
		{"ACRNACRNACRN", "ACRN"},
		{"QNXQVMBSQG  ", "QNX Hypervisor"},
	}
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
