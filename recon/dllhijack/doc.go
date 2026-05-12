// Package dllhijack discovers DLL-search-order hijack
// opportunities on Windows — places where an application
// loads a DLL from a user-writable directory BEFORE reaching
// the legitimate copy (typically in System32). Drop a DLL with
// the right name in the writable path and the operator's code
// runs the next time the victim loads.
//
// Discovery surface:
//
//   - [ScanServices] parses each service binary's PE import
//     table and emits Opportunities via DLL search-order
//     resolution.
//   - [ScanProcesses] reads live loaded-module lists from
//     every accessible process via Toolhelp32 — covers
//     runtime LoadLibrary, not just static imports.
//   - [ScanScheduledTasks] pulls every registered task's
//     exec actions via COM ITaskService and applies the same
//     PE-imports filter.
//   - [ScanAutoElevate] walks System32 .exes whose manifest
//     carries `autoElevate=true` (fodhelper, sdclt, …) — UAC
//     bypass vector.
//   - [ScanAll] aggregates the four.
//
// Validation + scoring:
//
//   - [Validate] drops a user-supplied canary DLL at an
//     Opportunity's HijackedPath, triggers the victim, polls
//     for a marker file, cleans up.
//   - [Rank] scores Opportunities (AutoElevate +
//     IntegrityGain weighted heavily).
//   - [SearchOrder] / [HijackPath] / [IsAutoElevate] are the
//     primitives callers can invoke on any (exe, dll) pair.
//
// `KnownDLLs` (HKLM\…\Session Manager\KnownDLLs) are excluded
// from hijack candidates — those are early-load-mapped from
// `\KnownDlls\` and bypass the search order entirely.
//
// ApiSet contracts (`api-ms-win-*.dll`, `ext-ms-win-*.dll`) are
// also excluded — the loader resolves them via the in-PEB
// ApiSet schema and never reads them from disk, so dropping a
// payload under those names would never be picked up. Some
// Win10/11 builds ship physical stubs in `System32\downlevel\`
// for compatibility; the filter prevents the file-existence
// heuristic from falsely flagging those.
//
// # MITRE ATT&CK
//
//   - T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)
//   - T1548.002 (Abuse Elevation Control Mechanism: Bypass UAC) — via [ScanAutoElevate]
//
// # Detection level
//
// moderate
//
// Writes to service directories + unusual DLL loads are
// logged by most modern EDRs; the unique signal is the
// mismatch between expected DLL location and actual load
// path. ScanAutoElevate hits combined with the canonical
// fodhelper / sdclt patterns are universally flagged.
//
// # Required privileges
//
// `ScanProcesses` and `ScanScheduledTasks` are unprivileged
// — Toolhelp32 + ITaskService both surface what the calling
// token can already see. `ScanServices` requires admin
// (`OpenSCManager(SC_MANAGER_ENUMERATE_SERVICE)` is
// unprivileged but `QueryServiceConfig` for the binary path
// of restricted services needs `SERVICE_QUERY_CONFIG` on the
// service object — admin in practice for the full SCM list).
// `ScanAutoElevate` reads PE manifests off disk in `System32`
// — unprivileged read access. Validation
// (`Validate(canary, ...)`) inherits the DACL of the
// candidate HijackedPath.
//
// # Platform
//
// Windows-only. Service / Toolhelp32 / ITaskService /
// `KnownDLLs` registry surface is Windows-only.
//
// # Example
//
// See [ExampleScanAll] in dllhijack_example_test.go.
//
// # See also
//
//   - docs/techniques/recon/dll-hijack.md
//   - [github.com/oioio-space/maldev/pe/dllproxy] — pure-Go forwarder DLL emitter, the natural payload generator for Opportunities surfaced here
//   - [github.com/oioio-space/maldev/pe/imports] — sibling PE import-table walker
//   - [github.com/oioio-space/maldev/persistence/service] — install hijacks via service binary path
//
// [github.com/oioio-space/maldev/pe/dllproxy]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/dllproxy
// [github.com/oioio-space/maldev/pe/imports]: https://pkg.go.dev/github.com/oioio-space/maldev/pe/imports
// [github.com/oioio-space/maldev/persistence/service]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service
package dllhijack
