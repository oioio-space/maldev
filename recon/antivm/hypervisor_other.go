//go:build !amd64

package antivm

// HypervisorPresent always returns false on non-amd64 builds —
// CPUID is an x86 / amd64 instruction with no portable analogue.
// Operators on arm64 / mips / s390x targets should use the
// platform-specific recon primitives (`recon/antivm.Detect`,
// `recon/sandbox`) instead.
func HypervisorPresent() bool { return false }

// HypervisorVendor always returns the empty string on non-amd64
// builds. See [HypervisorPresent] for the rationale.
func HypervisorVendor() string { return "" }

// CPUVendor always returns the empty string on non-amd64 builds —
// CPUID leaf 0 has no portable equivalent. Callers should treat the
// empty return as "vendor unknown" and skip vendor-keyed branches.
func CPUVendor() string { return "" }

// HypervisorVendorName lives in hypervisor.go (no build tag) so the
// friendly-name table is shared with the amd64 build.

// DefaultRDTSCThreshold mirrors the amd64 declaration so cross-
// platform code can reference the constant unconditionally. On
// non-amd64 builds it has no behavioural effect — RDTSCDelta
// always returns 0 and LikelyVirtualizedByTiming always returns
// false.
const DefaultRDTSCThreshold uint64 = 1000

// RDTSCDelta returns 0 on non-amd64 — there is no portable cycle
// counter analogue to RDTSC.
func RDTSCDelta(_ int) uint64 { return 0 }

// LikelyVirtualizedByTiming returns false on non-amd64 — no RDTSC
// means no timing signal.
func LikelyVirtualizedByTiming(_ uint64) bool { return false }

// cpuidHypervisorReport returns false / "" on non-amd64. Consumed
// by the cross-platform [Hypervisor] aggregator.
func cpuidHypervisorReport() (present bool, sig string) { return false, "" }
