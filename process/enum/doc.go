// Package enum provides cross-platform process enumeration —
// list every running process or find one by name / predicate.
//
// Platform-specific implementations:
//
//   - Windows: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` +
//     `Process32First` / `Process32Next` walking the snapshot.
//   - Linux: walk `/proc/<pid>/comm` and `/proc/<pid>/status`
//     for name + parent PID.
//
// `Process` is the shared cross-platform struct (`PID`, `PPID`,
// `Name`). Operators target this package to find lsass, taskmgr,
// or any other lookup-by-name workflow without dragging in a
// platform-specific dependency.
//
// # MITRE ATT&CK
//
//   - T1057 (Process Discovery)
//
// # Detection level
//
// quiet
//
// Process enumeration is standard operating-system behaviour
// used by every task manager and every legitimate IT tool.
// `CreateToolhelp32Snapshot` is one of the most-called Win32
// APIs on a typical desktop; `/proc` is read by `ps`, `top`,
// `htop`, and every container runtime. EDRs do not flag the
// enumeration itself; they correlate it against subsequent
// suspicious actions (lsass open, token theft).
//
// # Example
//
// See [ExampleFindByName] in enum_example_test.go.
//
// # See also
//
//   - docs/techniques/process/enum.md
//   - [github.com/oioio-space/maldev/credentials/lsassdump] — primary consumer (find lsass by name)
//   - [github.com/oioio-space/maldev/process/session] — sibling session / token enumeration
//
// [github.com/oioio-space/maldev/credentials/lsassdump]: https://pkg.go.dev/github.com/oioio-space/maldev/credentials/lsassdump
// [github.com/oioio-space/maldev/process/session]: https://pkg.go.dev/github.com/oioio-space/maldev/process/session
package enum
