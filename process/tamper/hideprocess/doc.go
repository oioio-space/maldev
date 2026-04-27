// Package hideprocess patches `NtQuerySystemInformation` in a
// target process so it returns `STATUS_NOT_IMPLEMENTED`,
// blinding that process's ability to enumerate running
// processes. Typically applied to taskmgr.exe, procexp.exe,
// or any per-user monitoring tool the operator wants
// neutralised.
//
// Mechanics:
//
//  1. Resolve the target's `ntdll.dll` base via
//     `NtQueryInformationProcess(ProcessBasicInformation)` →
//     PEB → Ldr.
//  2. Locate `NtQuerySystemInformation` export RVA.
//  3. Write a 7-byte `mov eax, STATUS_NOT_IMPLEMENTED;
//     ret 0x10` stub via `NtWriteVirtualMemory`.
//  4. Subsequent calls in the target return the patched
//     value; `Process32First`, `EnumProcesses`,
//     `GetExtendedTcpTable`-driven listings all return empty.
//
// The single entry point is [PatchProcessMonitor](pid, caller).
//
// # MITRE ATT&CK
//
//   - T1564.001 (Hide Artifacts: Hidden Process)
//   - T1027.005 (Indicator Removal from Tools) — local tooling neutralisation
//
// # Detection level
//
// moderate
//
// The target ntdll write itself is detectable — EDRs that
// continuously hash `.text` regions of ntdll across processes
// flag the patch. Practically very few EDRs do this (the
// hashing is expensive). Cross-correlation between an EDR
// reporting normal process activity and the target reporting
// no processes is a high-fidelity tell — but only if the
// defender is looking.
//
// # Example
//
// See [ExamplePatchProcessMonitor] in hideprocess_example_test.go.
//
// # See also
//
//   - docs/techniques/process/hideprocess.md
//   - [github.com/oioio-space/maldev/evasion/unhook] — sibling ntdll patching surface
//   - [github.com/oioio-space/maldev/win/syscall] — direct/indirect syscall caller
//
// [github.com/oioio-space/maldev/evasion/unhook]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/unhook
// [github.com/oioio-space/maldev/win/syscall]: https://pkg.go.dev/github.com/oioio-space/maldev/win/syscall
package hideprocess
