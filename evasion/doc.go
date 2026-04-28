// Package evasion is the umbrella for active EDR / AV evasion. It
// owns the [Technique] contract every sub-package implements plus the
// orchestration helpers (`ApplyAll`, `Apply`, `Caller` erasure) that
// let operators compose evasion stacks without importing each
// primitive directly.
//
// The [Technique] interface is the seam:
//
//	type Technique interface {
//	    Name() string
//	    Apply(c Caller) error
//	}
//
// Sub-packages (each ships its own `doc.go` with MITRE + detection
// level — list grouped by what the technique does):
//
//   - **In-process patching** — amsi, etw, unhook, hook,
//     hook/bridge, hook/shellcode (inline AMSI / ETW disable, ntdll
//     restore, JMP relay, IPC).
//   - **Sleep / dormancy** — sleepmask, callstack (Ekko / Foliage,
//     synthetic stack frames during dormant beacon windows).
//   - **Memory hardening** — acg, blockdlls, cet (Arbitrary Code
//     Guard, Block-Non-Microsoft DLLs, CET shadow stack hardening).
//   - **Anti-analysis** — antidebug, antivm, sandbox, timing, hwbp
//     (debugger / VM / sandbox / hardware-breakpoint detection;
//     `sandbox` orchestrates the others).
//   - **Process tampering** — fakecmd, hideprocess, phant0m,
//     herpaderping (PEB CommandLine spoof, Process-Hacker patch,
//     EventLog suspend, image-on-disk swap).
//   - **Filesystem stealth** — stealthopen (transactional NTFS
//     `Opener` interface).
//   - **Composition** — preset (pre-validated bundles like
//     "tier-1 implant" or "tier-3 hardened").
//
// `Caller` is intentionally `interface{}` to keep the umbrella
// cross-platform — Windows sub-packages cast to
// `*wsyscall.Caller` (may be nil to use standard WinAPI).
//
// # MITRE ATT&CK
//
//   - T1562.001 (Impair Defenses)
//   - T1497 (Virtualization/Sandbox Evasion)
//   - T1622 (Debugger Evasion)
//   - T1574.012 (Hijack Execution Flow: Inline Hooking)
//
// # Detection level
//
// per sub-package
//
// The umbrella itself is silent (interface dispatch only). Each
// sub-package documents its own detection level — they range from
// `quiet` (sleepmask region rotation) to `noisy` (`NtUnloadDriver`
// in unhook).
//
// # Example
//
// See [ExampleApplyAll] in evasion_example_test.go.
//
// # See also
//
//   - docs/techniques/evasion/README.md
//   - [github.com/oioio-space/maldev/evasion/preset] — pre-bundled
//     evasion stacks
//   - [github.com/oioio-space/maldev/win/syscall] — `*Caller` source
//     for the Caller-erasure parameter
//
// [github.com/oioio-space/maldev/evasion/preset]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/preset
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
package evasion
