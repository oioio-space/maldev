//go:build amd64

package antivm

import (
	"encoding/binary"
	"slices"
)

// cpuidRaw issues the CPUID instruction with EAX=leaf, ECX=subleaf
// and returns the four register outputs. Implemented in
// cpuid_amd64.s.
func cpuidRaw(leaf, subleaf uint32) (eax, ebx, ecx, edx uint32)

// HypervisorPresent reports whether `CPUID.1:ECX[31]` (the
// hypervisor-present bit) is set. Every commercial hypervisor
// (KVM, Xen, VMware, Hyper-V, Parallels, VirtualBox in HVM mode,
// modern QEMU/TCG) sets this bit unconditionally; bare-metal CPUs
// always clear it. The bit is defined by Intel/AMD as
// "reserved for use by the hypervisor to indicate its presence to
// guests" — it is intentionally a clean signal.
//
// Cheap (one CPUID), invisible to behavioural EDRs (CPUID is
// executed billions of times by ordinary userland), and resilient
// against the registry / DMI / process-name games that lighter
// `recon/antivm` checks lean on. Returns false on non-amd64 hosts.
func HypervisorPresent() bool {
	_, _, ecx, _ := cpuidRaw(1, 0)
	return ecx&(1<<31) != 0
}

// CPUVendor reads the 12-byte ASCII CPU vendor identification string
// from CPUID leaf 0 (EBX → EDX → ECX, per Intel SDM Vol. 2A) and
// returns it as a string. Stable across every x86-64 CPU and every
// hypervisor (the host CPU passes its own vendor through to guests
// that don't masquerade — VMware-tools "spoof CPUID" is the rare
// exception, and operators detecting it through this primitive are
// expected; that's the point).
//
// Common values:
//
//	"GenuineIntel" — Intel
//	"AuthenticAMD" — AMD
//	"CentaurHauls" — VIA / Centaur
//	"HygonGenuine" — Hygon (AMD licensee, China)
//
// Returns the empty string on non-amd64 hosts. Unlike
// [HypervisorVendor] this leaf is universal — every x86 CPU since the
// original Pentium implements it.
func CPUVendor() string {
	_, ebx, ecx, edx := cpuidRaw(0, 0)
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:4], ebx)
	binary.LittleEndian.PutUint32(b[4:8], edx)
	binary.LittleEndian.PutUint32(b[8:12], ecx)
	return string(b[:])
}

// HypervisorVendor reads the 12-byte ASCII vendor signature
// hypervisors expose at `CPUID.40000000h` (EBX:ECX:EDX). Returns
// the empty string when no hypervisor is present (bit clear), the
// leaf is unsupported, or the host is non-amd64.
//
// Common signatures (use [HypervisorVendorName] for a friendly
// label):
//
//	"VMwareVMware"     — VMware
//	"KVMKVMKVM\0\0\0"  — KVM
//	"Microsoft Hv"     — Hyper-V
//	"XenVMMXenVMM"     — Xen HVM
//	"TCGTCGTCGTCG"     — QEMU TCG (no hardware accel)
//	"VBoxVBoxVBox"     — VirtualBox (HVM)
//	"bhyve bhyve "     — bhyve
//	" lrpepyh vr"      — Parallels
//	"prl hyperv  "     — Parallels (newer builds)
//
// Operators commonly pair this with [HypervisorPresent]: a true
// from the bit + a recognised vendor string is the strongest
// "I'm in a sandbox/VM" signal CPUID can give.
func HypervisorVendor() string {
	if !HypervisorPresent() {
		return ""
	}
	_, ebx, ecx, edx := cpuidRaw(0x40000000, 0)
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:4], ebx)
	binary.LittleEndian.PutUint32(b[4:8], ecx)
	binary.LittleEndian.PutUint32(b[8:12], edx)
	return string(b[:])
}

// HypervisorVendorName lives in hypervisor.go (no build tag) so the
// friendly-name table is shared between amd64 and the non-amd64 stub
// build.

// rdtsc returns the current value of the CPU's 64-bit time-stamp
// counter. Implemented in rdtsc_amd64.s. Not serialised.
func rdtsc() uint64

// rdtscCpuidDelta returns the cycle delta around a single CPUID
// instruction (which forces a VMEXIT under HVM). Implemented in
// rdtsc_amd64.s.
func rdtscCpuidDelta() uint64

// DefaultRDTSCThreshold is the cycle threshold separating bare-metal
// CPUID latency (~30-50 cycles) from VMEXIT-augmented CPUID latency
// (500-3000+ cycles). Picked conservatively at 1000 — well above any
// observed bare-metal upper bound, well below any observed VM lower
// bound. Override via [LikelyVirtualizedByTiming]'s argument.
const DefaultRDTSCThreshold uint64 = 1000

// RDTSCDelta returns the median cycle delta of `samples` repeated
// CPUID-bracketed RDTSC reads. The median (rather than mean) filters
// out scheduler-induced outliers — Windows context switches between
// the two RDTSC reads can spike a single sample into the millions.
// Use 9 samples for a stable read; 1 is fine when the hot path
// matters more than absolute precision.
//
// Returns 0 if samples <= 0. On non-amd64 the stub returns 0.
//
// Cost: ~`samples * 50 cycles` on bare metal, ~`samples * 1500
// cycles` under HVM. Either way, sub-microsecond at any reasonable
// sample count.
func RDTSCDelta(samples int) uint64 {
	if samples <= 0 {
		return 0
	}
	deltas := make([]uint64, samples)
	for i := 0; i < samples; i++ {
		deltas[i] = rdtscCpuidDelta()
	}
	slices.Sort(deltas)
	return deltas[samples/2]
}

// cpuidHypervisorReport issues the present-bit + vendor-string
// CPUID pair in one shot and is consumed by [Hypervisor]. Avoids
// the redundant `CPUID.1` that would happen if the aggregator
// called [HypervisorPresent] then [HypervisorVendor] (the latter
// internally re-checks the present bit). Bare metal pays 1 CPUID;
// HVM pays 2.
func cpuidHypervisorReport() (present bool, sig string) {
	_, _, ecx, _ := cpuidRaw(1, 0)
	if ecx&(1<<31) == 0 {
		return false, ""
	}
	_, ebx, ecx, edx := cpuidRaw(0x40000000, 0)
	var b [12]byte
	binary.LittleEndian.PutUint32(b[0:4], ebx)
	binary.LittleEndian.PutUint32(b[4:8], ecx)
	binary.LittleEndian.PutUint32(b[8:12], edx)
	return true, string(b[:])
}

// LikelyVirtualizedByTiming returns true if the median CPUID-bracketed
// RDTSC delta exceeds threshold. Pass [DefaultRDTSCThreshold] for the
// canonical 1000-cycle cut-off; lower values catch lighter
// virtualisation (e.g. nested KVM with PV-CPUID hints) at the cost of
// more false positives on noisy hosts.
//
// This is the strongest signal CPUID-evading hypervisors leave behind
// — even when the VMM clears the `CPUID.1:ECX[31]` hypervisor bit
// (some custom builds do), it cannot hide the VMEXIT cost without
// trapping RDTSC itself, which most production hypervisors don't do
// because of the per-call overhead it would impose on every guest.
//
// Returns false on non-amd64 (the stub).
func LikelyVirtualizedByTiming(threshold uint64) bool {
	return RDTSCDelta(hypervisorTimingSamples) > threshold
}
