package antivm

import "errors"

// BackdoorVMwareReport is the result of a VMware backdoor probe.
//
// EBX/ECX/EDX hold the raw post-IN register values; they are zero when
// IsVMware is false (probe declined or no signature). When the probe
// runs to completion and EBX matches the VMware echo signature, IsVMware
// is true.
type BackdoorVMwareReport struct {
	// IsVMware is true when the backdoor I/O port responded with the
	// expected echo signature (EBX == "VMXh"). Always false when
	// PrivilegeOK is false (probe was declined for safety).
	IsVMware bool

	// PrivilegeOK is true when the host had the necessary I/O privileges
	// to issue the IN instruction without faulting. False on
	// unprivileged Windows / Linux without iopl(3) — the probe MUST
	// short-circuit because the IN would otherwise SIGSEGV.
	PrivilegeOK bool

	// Echo, ECX, EDX hold the raw register output of the IN. Zero unless
	// IsVMware is true. Echo is the EBX value (VMware echoes its magic
	// here); ECX usually carries the VMX-product type (1 = Express,
	// 2 = ESX, 3 = VMX, 4 = Workstation/Player).
	Echo uint32
	ECX  uint32
	EDX  uint32
}

// ErrBackdoorPrivilege fires when [BackdoorVMware] is invoked from a
// context that cannot safely issue port I/O (unprivileged user-mode on
// any modern OS). Callers should treat this as "VMware status unknown",
// not "definitely not VMware".
var ErrBackdoorPrivilege = errors.New("recon/antivm: VMware backdoor probe requires Ring 0 or CAP_SYS_RAWIO+iopl")

// BackdoorVMware probes the VMware-specific I/O backdoor at port 0x5658.
//
// On VMware guests, the hypervisor traps `IN EAX, DX` and echoes its
// magic ("VMXh") in EBX. On bare metal or non-VMware hypervisors the
// instruction faults with #GP at user level (IOPL is always 0 on modern
// OSes), which would crash the calling process — so this wrapper gates
// on a privilege check and returns [ErrBackdoorPrivilege] when it
// detects unprivileged execution.
//
// Caveats:
//   - Privilege check is conservative: even with CAP_SYS_RAWIO the
//     iopl(3) syscall may be blocked by seccomp / containerd profiles.
//     The function never executes the IN unless [hasPortIOPrivileges]
//     returned true.
//   - On Windows, port I/O from user mode is impossible regardless of
//     elevation — only kernel-mode (Ring 0) drivers can use it. The
//     Windows path therefore returns [ErrBackdoorPrivilege] always
//     unless the caller is in a kernel-mode context (e.g., a loaded
//     driver) — outside the scope of pure-Go.
//   - Other VMware-aware checks ([Hypervisor], CPUID leaf 0x40000000)
//     work in user mode and are usually sufficient. The backdoor port
//     is provided for the rare scenario where the operator already has
//     Ring 0 (e.g., via [kernel/driver/rtcore64]) and wants the most
//     specific possible signature.
//
// MITRE D3FEND: anti-VM detection. ATT&CK: T1497 (Virtualization /
// Sandbox Evasion).
func BackdoorVMware() (BackdoorVMwareReport, error) {
	if !hasPortIOPrivileges() {
		return BackdoorVMwareReport{}, ErrBackdoorPrivilege
	}
	defer dropPortIOPrivileges()
	var regs [4]uint32
	vmwareBackdoorRaw(vmwareMagic, vmwareCmdGetVersion, &regs)
	rep := BackdoorVMwareReport{
		PrivilegeOK: true,
		IsVMware:    regs[1] == vmwareSignature,
		Echo:        regs[1],
		ECX:         regs[2],
		EDX:         regs[3],
	}
	return rep, nil
}
