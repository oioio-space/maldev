// Package preset bundles `evasion.Technique` primitives into four
// validated risk levels for one-shot deployment.
//
//   - Minimal — patches AMSI ScanBuffer + ETW user-mode write helpers.
//     Lowest detection surface; suitable for droppers and initial
//     access.
//   - Stealth — Minimal + selective ntdll unhooking of ~10 commonly
//     hooked NT functions (NtAllocateVirtualMemory, NtCreateThreadEx,
//     etc.). Suitable for post-exploitation tools that need injection
//     primitives without inline-hook interference.
//   - Hardened — sits between Stealth and Aggressive: AMSI + ETW + full
//     ntdll unhook + CET opt-out. Drops the per-process mitigations
//     (ACG, BlockDLLs) that prevent further RWX / non-MS DLL loads, so
//     callers can still inject afterwards. Use this on Win11+ CET hosts
//     where the smaller Stealth bundle would let APC-delivered
//     shellcode trip on ENDBR64.
//   - Aggressive — Stealth + full ntdll unhook + CET opt-out + ACG +
//     BlockDLLs. Maximum evasion but irreversible: ACG blocks
//     subsequent `VirtualAlloc(PAGE_EXECUTE)`, so apply only AFTER your
//     shellcode allocation has completed. Suitable for red-team finals
//     and assumed-breach scenarios.
//
// Every preset returns a `[]evasion.Technique` consumable by
// `evasion.ApplyAll(slice, caller)`. CETOptOut is also exported as a
// standalone Technique so callers building their own slice can include
// it without rolling the wrapper themselves; on hosts where CET is not
// enforced the underlying call short-circuits to nil.
//
// # What is NOT a preset Technique
//
// `evasion/sleepmask` and `evasion/callstack` are deliberately absent
// from every preset slice. They are not one-shot Apply-and-forget
// primitives:
//
//   - `sleepmask` runs interactively — the operator decides when to
//     enter masked sleep, and the duration depends on beacon cadence.
//     A preset that called `Sleep` once at apply time would just block
//     the implant for an arbitrary period and then return to a
//     fully-visible state.
//   - `callstack` provides metadata to a SpoofCall pivot (a chain of
//     fake frames the operator plants on a thread's stack). There is
//     no "apply" semantics — the value is consumed at call sites that
//     need to spoof their own call stack, not in a process-wide setup.
//
// Treat the two as composable layers around the preset, not members
// of it.
//
// # MITRE ATT&CK
//
// Inherits the T-IDs of the techniques composed:
//
//   - T1562.001 (Impair Defenses: Disable or Modify Tools)
//
// # Detection level
//
// varies
//
// Equals the loudest composed technique. Minimal is `quiet`; Stealth
// is `moderate`; Hardened is `moderate` (full unhook is the loudest
// bit but the per-process mitigations are absent); Aggressive is
// `noisy` (full ntdll `.text` rewrite + ACG/BlockDLLs trail).
//
// # Example
//
// See [ExampleStealth] in preset_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/preset.md
//   - [github.com/oioio-space/maldev/evasion] — `ApplyAll` consumer
//
// [github.com/oioio-space/maldev/evasion]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion
package preset
