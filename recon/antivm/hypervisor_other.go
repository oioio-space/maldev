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

// HypervisorVendorName lives in hypervisor.go (no build tag) so the
// friendly-name table is shared with the amd64 build.
