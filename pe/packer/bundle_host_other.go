//go:build !amd64 || (!linux && !windows)

package packer

// HostCPUIDVendor returns the zero value on non-amd64 or unsupported
// OS — there is no portable CPUID without inline asm. Bundles built
// for these platforms should rely on PT_MATCH_ALL or omit
// PT_CPUID_VENDOR predicates.
func HostCPUIDVendor() [12]byte { return [12]byte{} }

// MatchBundleHost returns -1 (no match) on non-amd64 or unsupported
// OS — the asm primitives the runtime evaluator relies on do not have
// portable equivalents.
func MatchBundleHost(bundle []byte) (int, error) { return -1, nil }
