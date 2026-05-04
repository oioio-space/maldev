//go:build amd64

package antivm

import "encoding/binary"

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
