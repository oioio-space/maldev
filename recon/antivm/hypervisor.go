package antivm

// hypervisorVendors maps every recognised `CPUID.40000000h`
// vendor signature (12 ASCII bytes) to its friendly product name.
// Keep entries sorted by vendor for grep-ability when adding new
// hypervisors.
var hypervisorVendors = map[string]string{
	"VMwareVMware":        "VMware",
	"KVMKVMKVM\x00\x00\x00": "KVM",
	"Microsoft Hv":        "Hyper-V",
	"XenVMMXenVMM":        "Xen",
	"TCGTCGTCGTCG":        "QEMU/TCG",
	"VBoxVBoxVBox":        "VirtualBox",
	"bhyve bhyve ":        "bhyve",
	" lrpepyh vr":         "Parallels",
	"prl hyperv  ":        "Parallels",
	"ACRNACRNACRN":        "ACRN",
	"QNXQVMBSQG  ":        "QNX Hypervisor",
}

// HypervisorVendorName maps a raw [HypervisorVendor] signature to
// a friendly display string ("VMware", "KVM", "Hyper-V", …).
// Returns the empty string when sig is empty or the signature is
// not on the recognised-vendor list — callers can still surface
// the raw 12-byte string in that case for forensic value.
//
// Cross-platform: the same map is used regardless of GOARCH so a
// Linux analyst inspecting a Windows captured signature can resolve
// it without a build-tag wrapper.
func HypervisorVendorName(sig string) string { return hypervisorVendors[sig] }
