// Package fakecmd overwrites the current process's PEB
// `CommandLine` UNICODE_STRING so process-listing tools
// (Process Explorer, `wmic`, `Get-Process`, Task Manager)
// display a fake command-line instead of the real one.
//
// Three primitives:
//
//   - [Spoof] — overwrite the current process's PEB
//     CommandLine. The kernel `EPROCESS` retains the original
//     so SACL forensics still see the real launch line; user-mode
//     tooling sees the fake.
//   - [SpoofPID] — overwrite a target process's CommandLine
//     via `NtWriteVirtualMemory`. Requires `PROCESS_VM_WRITE`.
//   - [Restore] — write the original CommandLine back, useful
//     in defer-style cleanup so a long-running process doesn't
//     ship the fake line into telemetry post-task.
//
// All entry points accept an optional `*wsyscall.Caller` (nil
// = WinAPI fallback) so callers can route through direct /
// indirect syscalls.
//
// # MITRE ATT&CK
//
//   - T1036.005 (Masquerading: Match Legitimate Name or Location)
//   - T1564 (Hide Artifacts) — generic obfuscation
//
// # Detection level
//
// quiet
//
// In-memory only — kernel `EPROCESS.ProcessParameters` retains
// the original. PEB-based spoofs do not show up in
// `ProcessHacker` / Process Explorer's "Image" view by default,
// only in the "Command Line" property tab. Forensic acquisition
// of the live system (or a memory dump) reveals both values
// side-by-side.
//
// # Example
//
// See [ExampleSpoof] in fakecmd_example_test.go.
//
// # See also
//
//   - docs/techniques/process/fakecmd.md
//   - [github.com/oioio-space/maldev/pe/masquerade] — pair to clone svchost identity at PE level
//   - [github.com/oioio-space/maldev/win/syscall] — direct/indirect syscall caller
//
// [github.com/oioio-space/maldev/pe/masquerade]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/masquerade
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
package fakecmd
