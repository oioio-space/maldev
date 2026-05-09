//go:build windows && amd64

package antivm

// hasPortIOPrivileges always returns false on Windows. Port I/O from
// user mode is impossible regardless of token elevation — only Ring 0
// (kernel-mode driver) code can issue IN/OUT, and a pure-Go binary
// always runs at CPL 3.
//
// The user-mode VMware-detection arsenal already covers most cases:
//   - [Hypervisor] reads CPUID 0x40000000 vendor string ("VMwareVMware").
//   - [Detect] / [DetectAll] inspect product/system DMI strings.
// The backdoor port is documented for completeness but unreachable from
// the operator-facing pure-Go shell on Windows.
func hasPortIOPrivileges() bool { return false }

// dropPortIOPrivileges is a no-op on Windows — privilege was never
// raised. Kept for the symmetric API the linux build expects.
func dropPortIOPrivileges() {}
