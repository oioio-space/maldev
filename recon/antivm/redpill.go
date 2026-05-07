package antivm

// RedpillReport aggregates the SIDT / SGDT / SLDT readings into a
// single VM-likely verdict. Joanna Rutkowska's 2004 "Red Pill"
// paper observed that pre-VT-x hypervisors had to relocate guest
// descriptor tables out of the canonical kernel-half address
// range, producing bases that bare metal would never emit. The
// signal is largely historical on modern hardware-virtualized
// guests (VT-x / AMD-V back the IDTR/GDTR with VMCS state that
// looks identical to bare metal), but composes cheaply with the
// [Hypervisor] CPUID + RDTSC stack and still catches some
// emulators / older nested-virt configurations.
//
// All fields are zero on non-amd64 builds; LikelyVM is false.
type RedpillReport struct {
	// IDTBase / IDTLimit / GDTBase / GDTLimit are the raw values
	// returned by the SIDT and SGDT instructions. On bare-metal
	// x86-64 both bases sit in the canonical kernel half
	// (`0xffff8000_00000000` upward).
	IDTBase  uint64
	IDTLimit uint16
	GDTBase  uint64
	GDTLimit uint16

	// LDT is the SLDT-returned 16-bit segment selector. Zero on
	// modern Windows / Linux; legacy hypervisors sometimes leave
	// it non-zero.
	LDT uint16

	// IDTSuspect / GDTSuspect / LDTSuspect mark each individual
	// signal. The IDT/GDT flags fire when the base falls outside
	// the canonical kernel half; the LDT flag fires on any
	// non-zero selector.
	IDTSuspect bool
	GDTSuspect bool
	LDTSuspect bool

	// LikelyVM is the OR of every individual suspect flag. Same
	// "any positive signal wins" policy as
	// [HypervisorReport.LikelyVM].
	LikelyVM bool
}

// Probe runs the full Red Pill triplet (SIDT + SGDT + SLDT) and
// returns the aggregated [RedpillReport]. Each instruction is a
// single user-mode CPU op; the call is sub-microsecond on bare
// metal. Safe to call from any goroutine.
//
// On non-amd64 returns a zero-valued report (LikelyVM=false).
// Operators bailing on a sandbox should chain this with
// [Hypervisor]: a positive Red Pill signal alongside a negative
// hypervisor-CPUID signal is the rare-but-loud "old emulator"
// case.
func Probe() RedpillReport { return redpillProbe() }
