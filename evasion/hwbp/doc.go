// Package hwbp provides detection and clearing of hardware breakpoints
// set by EDR products on NT function prologues.
//
// Technique: Hardware debug register (DR0-DR7) manipulation to detect and
// remove EDR monitoring points that survive ntdll unhooking.
// MITRE ATT&CK: T1622 (Debugger Evasion)
// Detection: Medium — modifying debug registers is unusual but not inherently
// malicious. Some EDRs monitor SetThreadContext calls.
// Platform: Windows.
//
// How it works: EDRs like CrowdStrike set hardware breakpoints (DR0-DR3) on
// NT function prologues instead of inline hooks. These persist even after
// ntdll is unhooked from disk. This package reads debug registers via
// GetThreadContext, identifies breakpoints pointing into ntdll, and clears
// them via SetThreadContext on all threads in the process.
//
// Limitations:
//   - Must enumerate and modify ALL threads — missed threads retain breakpoints.
//   - SetThreadContext is itself monitored by some EDRs.
//   - Hardware breakpoints are limited to 4 (DR0-DR3); if all are used by EDR,
//     clearing them removes all monitoring.
//
// Example:
//
//	bps, _ := hwbp.Detect()
//	if len(bps) > 0 {
//	    hwbp.ClearAll()
//	}
package hwbp
