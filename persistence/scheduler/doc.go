// Package scheduler creates, deletes, lists, and runs Windows
// scheduled tasks via the COM `ITaskService` API — no
// `schtasks.exe` child process.
//
// Instantiates the `Schedule.Service` COM object via go-ole,
// builds an `ITaskDefinition` with trigger / action / settings,
// and registers it through `ITaskFolder::RegisterTaskDefinition`.
// Supports logon, startup, daily, and one-shot time triggers;
// tasks may be flagged hidden so they don't appear in
// `taskschd.msc` without the operator pressing the "Show hidden
// tasks" toggle.
//
// Task names must start with a backslash: `\TaskName` for the
// root folder, or `\Folder\TaskName` inside a subfolder.
// Startup / logon triggers require elevation.
//
// # MITRE ATT&CK
//
//   - T1053.005 (Scheduled Task/Job: Scheduled Task)
//
// # Detection level
//
// moderate
//
// Task registration emits Event ID 4698 (security log,
// "scheduled task created") regardless of how the task is
// created — `schtasks.exe`, COM, or PowerShell all hit the same
// audit hook. The COM path *avoids* `schtasks.exe`-spawn
// telemetry (Sysmon Event 1, child-process EDR rules), which
// some defender stacks rely on more heavily than the 4698
// audit. Hidden flag does not suppress logging.
//
// # Required privileges
//
// unprivileged for per-user tasks (root folder, time / logon
// triggers tied to the calling user). admin for tasks that
// run as SYSTEM, tasks under `\Microsoft\` or hidden folders,
// and tasks with `WithTriggerStartup()` (boot trigger). The
// `WithRunLevel(TASK_RUNLEVEL_HIGHEST)` flag does NOT elevate
// — it preserves elevation if the caller already has it.
// SYSTEM works without elevation.
//
// # Platform
//
// Windows-only. Sits on the COM `Schedule.Service` object
// (`ITaskService` / `ITaskFolder` / `IRegisteredTask`) via
// go-ole; no POSIX equivalent. Linux cron / systemd timer
// integration is out of scope.
//
// # Example
//
// See [ExampleCreate] in scheduler_example_test.go.
//
// # See also
//
//   - docs/techniques/persistence/task-scheduler.md
//   - [github.com/oioio-space/maldev/persistence/service] — sibling SYSTEM-scope persistence
//   - [github.com/oioio-space/maldev/cleanup] — remove the task post-op
//
// [github.com/oioio-space/maldev/persistence/service]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/service
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
package scheduler
