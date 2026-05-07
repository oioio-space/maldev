//go:build amd64

package antivm

import "encoding/binary"

// sidtRaw stores the 10-byte IDT pseudo-descriptor (2-byte limit
// + 8-byte base) at *buf. Implemented in redpill_amd64.s.
func sidtRaw(buf *byte)

// sgdtRaw stores the 10-byte GDT pseudo-descriptor at *buf.
// Implemented in redpill_amd64.s.
func sgdtRaw(buf *byte)

// sldtRaw stores the 2-byte LDT segment selector at *buf.
// Implemented in redpill_amd64.s.
func sldtRaw(buf *byte)

// SIDT issues the SIDT instruction and returns the IDT base
// address as a uint64 (the upper 8 bytes of the pseudo-descriptor)
// plus the limit. SIDT is unprivileged in CPL3 (user mode) — that
// is precisely why Joanna Rutkowska's 2004 "Red Pill" leveraged it
// to peek at kernel-mapped descriptor tables from userland.
//
// On bare-metal Windows / Linux x86-64 the IDT base sits in the
// canonical kernel-half range (`0xffff8000_00000000` upward).
// Older VMware / Virtual PC / VirtualBox hypervisors relocated
// per-guest IDTs into ranges that bare metal would never produce —
// the original Red Pill check spotted that anomaly. Modern
// hardware-virtualized guests (VT-x, AMD-V) use VMCS-backed IDTRs
// that look identical to bare metal, so this signal is largely
// historical; treat it as one input among many in
// [HypervisorReport.LikelyVM].
//
// Returns base=0, limit=0 on non-amd64. Panics if the OS prevents
// SIDT (e.g., kernel-mode UMIP is enabled on Linux ≥ 5.4 with
// the CR4.UMIP bit set — userland sees `#GP`); operators bailing
// on a sandbox should treat any panic from this routine as
// "VM-likely" rather than "bare-metal".
func SIDT() (base uint64, limit uint16) {
	var buf [10]byte
	sidtRaw(&buf[0])
	limit = binary.LittleEndian.Uint16(buf[0:2])
	base = binary.LittleEndian.Uint64(buf[2:10])
	return base, limit
}

// SGDT mirrors [SIDT] for the Global Descriptor Table. Same
// caveats: unprivileged, historically a Red Pill signal, weak on
// modern VT-x / AMD-V. Returns base=0, limit=0 on non-amd64.
func SGDT() (base uint64, limit uint16) {
	var buf [10]byte
	sgdtRaw(&buf[0])
	limit = binary.LittleEndian.Uint16(buf[0:2])
	base = binary.LittleEndian.Uint64(buf[2:10])
	return base, limit
}

// SLDT mirrors [SIDT] for the Local Descriptor Table. The LDT is
// almost always empty on modern Windows / Linux (selector = 0);
// some legacy VM configurations leave it non-zero. Returns 0 on
// non-amd64.
func SLDT() uint16 {
	var buf [2]byte
	sldtRaw(&buf[0])
	return binary.LittleEndian.Uint16(buf[0:2])
}

// kernelHalfMask is the 17-bit canonical-kernel prefix on x86-64
// (bits 47..63 set). Bare-metal Windows / Linux place the IDT and
// GDT bases in this half; older hypervisors that relocated them
// into low addresses produced bases that fail this mask.
const kernelHalfMask uint64 = 0xffff800000000000

// redpillProbe runs the SIDT/SGDT/SLDT triplet and computes a
// per-source verdict. Used by [Hypervisor] when assembling the
// aggregated [HypervisorReport].
func redpillProbe() RedpillReport {
	idtBase, idtLimit := SIDT()
	gdtBase, gdtLimit := SGDT()
	ldt := SLDT()

	// Bare-metal x86-64 always reports IDT/GDT bases in the
	// canonical kernel half. A base outside that range is the
	// classical Red Pill signal — it implies a hypervisor (or an
	// unusual emulator) installed a per-guest descriptor table at
	// a userland-looking address.
	idtSuspect := idtBase != 0 && idtBase&kernelHalfMask != kernelHalfMask
	gdtSuspect := gdtBase != 0 && gdtBase&kernelHalfMask != kernelHalfMask
	// LDT non-zero is uncommon on modern kernels; flag it.
	ldtSuspect := ldt != 0

	return RedpillReport{
		IDTBase:    idtBase,
		IDTLimit:   idtLimit,
		GDTBase:    gdtBase,
		GDTLimit:   gdtLimit,
		LDT:        ldt,
		IDTSuspect: idtSuspect,
		GDTSuspect: gdtSuspect,
		LDTSuspect: ldtSuspect,
		LikelyVM:   idtSuspect || gdtSuspect || ldtSuspect,
	}
}
