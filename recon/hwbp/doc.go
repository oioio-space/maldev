// Package hwbp detects and clears hardware breakpoints set by
// EDR products on NT function prologues — surviving the
// classic ntdll-on-disk-unhook pass.
//
// Hardware debug registers DR0-DR3 hold breakpoint addresses;
// DR6 / DR7 carry status / control. EDRs (CrowdStrike, S1)
// place HWBPs on `Nt*` prologues to monitor them without
// modifying ntdll's `.text` — so the unhook-from-disk
// technique that defeats inline hooks does not defeat HWBPs.
//
// `Detect` reads DR0-DR3 via `GetThreadContext` on every
// thread and returns breakpoints that point inside ntdll;
// [DetectAll] returns every set HWBP regardless of target.
// [ClearAll] zeros the registers via `SetThreadContext` on
// every thread.
//
// # MITRE ATT&CK
//
//   - T1622 (Debugger Evasion)
//   - T1027.005 (Indicator Removal from Tools) — neutralising EDR HWBPs
//
// # Detection level
//
// moderate
//
// Modifying debug registers is unusual but not inherently
// malicious; some EDRs flag `SetThreadContext` calls. Every
// thread must be enumerated and patched — missed threads
// retain breakpoints. Restoring HWBPs to non-zero state from
// user-mode requires kernel-context aware bypasses on Win11.
//
// # Example
//
// See [ExampleDetect] in hwbp_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/hw-breakpoints.md
//   - [github.com/oioio-space/maldev/evasion/unhook] — pair: HWBP clear + ntdll unhook
//   - [github.com/oioio-space/maldev/win/syscall] — direct/indirect syscalls survive both inline + HWBP
//
// [github.com/oioio-space/maldev/evasion/unhook]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
package hwbp
