// Package preset bundles `evasion.Technique` primitives into three
// validated risk levels for one-shot deployment.
//
//   - Minimal — patches AMSI ScanBuffer + ETW user-mode write helpers.
//     Lowest detection surface; suitable for droppers and initial
//     access.
//   - Stealth — Minimal + selective ntdll unhooking of ~10 commonly
//     hooked NT functions (NtAllocateVirtualMemory, NtCreateThreadEx,
//     etc.). Suitable for post-exploitation tools that need injection
//     primitives without inline-hook interference.
//   - Aggressive — Stealth + full ntdll unhook + ACG + BlockDLLs.
//     Maximum evasion but irreversible: ACG blocks subsequent
//     `VirtualAlloc(PAGE_EXECUTE)`, so apply only AFTER your shellcode
//     allocation has completed. Suitable for red-team finals and
//     assumed-breach scenarios.
//
// Every preset returns a `[]evasion.Technique` consumable by
// `evasion.ApplyAll(slice, caller)`.
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
// is `moderate`; Aggressive is `noisy` (full ntdll `.text` rewrite is
// visible to integrity scans).
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
