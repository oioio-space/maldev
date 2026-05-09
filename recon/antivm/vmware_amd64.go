//go:build amd64

package antivm

// vmwareBackdoorRaw issues `IN EAX, DX` against the VMware backdoor I/O
// port (0x5658) with EAX = eaxIn and ECX = ecxIn. Post-IN register
// values are stored into regs in [EAX, EBX, ECX, EDX] order.
//
// MUST NOT be called from unprivileged code: on bare metal (or any host
// where the hypervisor doesn't trap the I/O instruction) the IN faults
// with #GP and crashes the process. [BackdoorVMware] is the safe
// high-level entry that gates on CAP_SYS_RAWIO / Administrator first.
//
// Implemented in vmware_amd64.s.
func vmwareBackdoorRaw(eaxIn, ecxIn uint32, regs *[4]uint32)

// VMware backdoor protocol constants. Documented in VMware's open-vm-tools
// repo: lib/include/backdoor_def.h.
const (
	// vmwareMagic is the value set in EAX before the IN instruction.
	// On a VMware hypervisor, the trap handler matches on this value
	// to confirm the call originates from a guest's backdoor caller.
	vmwareMagic uint32 = 0x564D5868 // "VMXh"

	// vmwarePort is the I/O port number the backdoor listens on (0x5658
	// = "VX"). Loaded into DX before the IN.
	vmwarePort uint32 = 0x5658

	// vmwareCmdGetVersion is the backdoor command for "what hypervisor
	// version am I running on?". Returns version magic in EBX.
	vmwareCmdGetVersion uint32 = 0x0A
)

// vmwareSignature is the value VMware returns in EBX after a successful
// CMD_GETVERSION call. Identical to vmwareMagic by convention — the
// hypervisor echoes the magic to confirm the trap was honoured.
const vmwareSignature uint32 = vmwareMagic
