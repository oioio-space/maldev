// Package hideprocess patches a target process's user-mode
// process-enumeration surface so it returns empty / failed
// results — blinding monitoring tools without killing them.
// Typically applied to taskmgr.exe, procexp.exe, or any
// per-user watchdog the operator wants neutralised.
//
// Four entry points cover the three Win32 enumeration paths:
//
//  1. [PatchProcessMonitor] — patches `ntdll!NtQuerySystemInformation`
//     to return `STATUS_NOT_IMPLEMENTED`. Blinds every Win32
//     enumeration that bottoms out in the Nt-level call (Task
//     Manager, `tasklist.exe`, ProcessHacker default view, native
//     PEB walks). 6-byte stub.
//
//  2. [PatchEnumProcesses] — patches `kernel32!K32EnumProcesses`
//     to `xor eax, eax; ret`. `psapi!EnumProcesses` is a
//     forwarder that resolves to the kernel32 implementation, so
//     both clients land on the same patched bytes. 3-byte stub.
//
//  3. [PatchToolhelp] — patches `kernel32!Process32FirstW` and
//     `Process32NextW` to the same 3-byte BOL=FALSE stub. Snapshots
//     produced via `CreateToolhelp32Snapshot` walk return FALSE
//     on the first iteration and look empty.
//
//  4. [PatchAll] — applies the three above in order
//     (NQSI → K32EnumProcesses → Process32{First,Next}W). Stops
//     at the first error and wraps it with the failing step's
//     name. Idempotent — re-running rewrites the same bytes.
//
// All entry points share the same target-side mechanics:
//
//  1. `OpenProcess(VM_WRITE | VM_OPERATION | QUERY_INFORMATION)`.
//  2. Resolve the export's in-process address — kernel32/ntdll
//     load at the same VA in every process per boot, so the
//     local address equals the remote address.
//  3. Write the patch via `NtWriteVirtualMemory` (when a
//     `*wsyscall.Caller` is supplied) or
//     `VirtualProtectEx + WriteProcessMemory` fallback.
//
// What is NOT covered: WMI `Win32_Process` (runs inside
// `wmiprvse.exe`, would need separate cross-process injection)
// and kernel-source enumeration (EDR drivers, Sysmon Event ID 1,
// ETW Threat-Intelligence). See `docs/techniques/process/hideprocess.md`
// "Coverage matrix" for the structural reasoning.
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
// The target write itself is detectable — EDRs that continuously
// hash `.text` regions of `ntdll`/`kernel32` across processes
// flag the patches. Practically very few EDRs do this (the
// hashing is expensive). Cross-correlation between an EDR
// reporting normal process activity and the target reporting
// no processes is a high-fidelity tell — but only if the
// defender is looking.
//
// # Required privileges
//
// admin or an own-token-owned target —
// `PROCESS_VM_WRITE | PROCESS_VM_OPERATION` is the gate; in
// practice operators reach for `SeDebugPrivilege`.
//
// # Platform
//
// Windows-only. The non-Windows stub returns
// `errors.New("hideprocess: not supported on this platform")`
// for every entry point.
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
