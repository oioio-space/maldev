// Package phant0m suppresses Windows Event Log recording by
// terminating the EventLog service threads inside the hosting
// `svchost.exe` — the service stays "Running" in the SCM
// listing but no new entries are written.
//
// Mechanics:
//
//  1. Enumerate svchost.exe processes; identify the one
//     hosting the EventLog service (`svchost.exe -k LocalServiceNetworkRestricted`
//     on modern Windows).
//  2. List its threads via `NtQuerySystemInformation(SystemProcessInformation)`
//     or `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`.
//  3. Open each thread (`OpenThread(THREAD_TERMINATE)`) and
//     call `TerminateThread` individually.
//
// SCM still reports "Running" because the *process* is alive —
// only the worker threads of the EventLog service inside the
// shared host are dead. New writes via `ReportEvent` /
// `EvtReportEvent` queue but never persist.
//
// # MITRE ATT&CK
//
//   - T1562.002 (Impair Defenses: Disable Windows Event Logging)
//
// # Detection level
//
// noisy
//
// Killing EventLog threads is itself an event the EventLog
// service would log — but it can't. Mature SOCs detect the
// gap: EventLog entries stop arriving, the service shows
// "Running", a heartbeat probe (Defender, MDE, custom
// tripwire) fires. Sysmon Event ID 8 (CreateRemoteThread)
// against svchost.exe + Sysmon Event ID 10 (ProcessAccess)
// with `THREAD_TERMINATE` are the kernel-side telemetry
// most EDRs ship by default.
//
// # Required privileges
//
// admin + `SeDebugPrivilege`. The hosting svchost runs as
// `NT AUTHORITY\LocalService`; opening it with
// `PROCESS_QUERY_LIMITED_INFORMATION` works for any user,
// but `OpenThread(THREAD_TERMINATE)` against another
// service's threads requires `SeDebugPrivilege` (admin).
// SYSTEM works without elevation. The `Heartbeat` ticker
// inherits the same gate.
//
// # Platform
//
// Windows-only. EventLog service + svchost shared-host
// architecture + the `I_QueryTagInformation` advapi32 export
// used to scope termination to EventLog threads are all
// Windows-specific.
//
// # Example
//
// See [ExampleKill] in phant0m_example_test.go.
//
// # See also
//
//   - docs/techniques/process/phant0m.md
//   - [github.com/oioio-space/maldev/evasion/etw] — sibling logging-suppression surface (per-process ETW)
//   - [github.com/oioio-space/maldev/cleanup] — pair to clean log artefacts at op end
//
// [github.com/oioio-space/maldev/evasion/etw]: https://pkg.go.dev/github.com/oioio-space/maldev/evasion/etw
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
package phant0m
