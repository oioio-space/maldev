package antivm

// hypervisorVendors maps every recognised `CPUID.40000000h`
// vendor signature (12 ASCII bytes) to its friendly product name.
// Display strings match `DefaultVendors[].Name` so the package
// emits one canonical name per hypervisor regardless of detection
// axis (registry, DMI, NIC, CPUID). Map literal sorted by display
// name for grep-ability.
var hypervisorVendors = map[string]string{
	"ACRNACRNACRN":          "ACRN",
	" lrpepyh vr":           "Parallels",
	"prl hyperv  ":          "Parallels",
	"bhyve bhyve ":          "bhyve",
	"KVMKVMKVM\x00\x00\x00": "KVM",
	"Microsoft Hv":          "Hyper-V",
	"QNXQVMBSQG  ":          "QNX Hypervisor",
	"TCGTCGTCGTCG":          "QEMU",
	"VBoxVBoxVBox":          "VirtualBox",
	"VMwareVMware":          "VMware",
	"XenVMMXenVMM":          "Xen",
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

// hypervisorTimingSamples is the sample count [Hypervisor] feeds to
// [RDTSCDelta]. 9 is small enough to keep the aggregator under 100µs
// on bare metal but large enough to filter the worst scheduler
// outliers via the median. Internal — callers wanting a custom
// sample count call [RDTSCDelta] directly.
const hypervisorTimingSamples = 9

// HypervisorReport aggregates every CPUID/timing-based hypervisor
// signal into a single struct. Returned by [Hypervisor]; consumers
// that want a quick yes/no read [HypervisorReport.LikelyVM].
type HypervisorReport struct {
	// Present mirrors [HypervisorPresent] — `CPUID.1:ECX[31]`. Set
	// by every commercial hypervisor; clear on bare metal.
	Present bool

	// VendorSig is the raw 12-byte ASCII signature from
	// `CPUID.40000000h` (EBX:ECX:EDX). Empty when Present is false.
	VendorSig string

	// VendorName is the friendly label resolved via
	// [HypervisorVendorName]. Empty when VendorSig is empty OR when
	// the signature is non-empty but unrecognised — callers can
	// distinguish the two cases by looking at VendorSig.
	VendorName string

	// TimingDelta is the median CPUID-bracketed RDTSC delta in
	// cycles, sampled [hypervisorTimingSamples] times. Bare-metal:
	// ~30-100. Under HVM: 500-3000+. Zero on non-amd64.
	TimingDelta uint64

	// LikelyVM is the OR of every individual signal: Present is
	// true, VendorSig is non-empty, OR TimingDelta exceeds
	// [DefaultRDTSCThreshold]. The "any positive signal wins"
	// policy is intentional — operators bailing on a sandbox
	// usually want false-positives over false-negatives.
	LikelyVM bool
}

// Hypervisor runs all CPUID/timing-based hypervisor probes and
// returns the aggregated [HypervisorReport]. Issues at most 2
// CPUIDs for the present+vendor pair (1 on bare metal, since the
// vendor probe is skipped when the present bit is clear) plus
// [hypervisorTimingSamples] RDTSC-bracketed CPUIDs — sub-microsecond
// on bare metal, sub-100µs under HVM. Safe to call from any
// goroutine.
//
// On non-amd64 the report has Present=false, VendorSig="",
// TimingDelta=0, and LikelyVM=false — operators on those targets
// should fall back to [Detect] / [DetectAll] for the
// registry/file/NIC dimensions.
func Hypervisor() HypervisorReport {
	present, sig := cpuidHypervisorReport()
	delta := RDTSCDelta(hypervisorTimingSamples)
	var name string
	if sig != "" {
		name = HypervisorVendorName(sig)
	}
	return HypervisorReport{
		Present:     present,
		VendorSig:   sig,
		VendorName:  name,
		TimingDelta: delta,
		LikelyVM:    present || sig != "" || delta > DefaultRDTSCThreshold,
	}
}
