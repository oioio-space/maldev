// Package scheduler creates, deletes, lists and runs Windows scheduled tasks
// via the COM ITaskService API — no schtasks.exe child process.
//
// Technique: Windows Task Scheduler persistence via COM (Schedule.Service).
// MITRE ATT&CK: T1053.005 (Scheduled Task/Job: Scheduled Task)
// Platform: Windows
// Detection: Medium — task registration is still logged (Event ID 4698),
// but no schtasks.exe child process is spawned (evades Sysmon Event ID 1
// and child-process EDR telemetry).
//
// How it works: Instantiates the Schedule.Service COM object via go-ole,
// builds an ITaskDefinition with trigger/action/settings, and registers it
// through ITaskFolder.RegisterTaskDefinition. Supports logon, startup,
// daily and one-shot time triggers; tasks may be flagged hidden.
//
// Task names must start with a backslash: `\TaskName` for the root folder,
// or `\Folder\TaskName` inside a subfolder.
//
// Example:
//
//	err := scheduler.Create(`\MyTask`,
//	    scheduler.WithAction(`C:\payload.exe`),
//	    scheduler.WithTriggerLogon(),
//	    scheduler.WithHidden(),
//	)
//
// Startup/logon triggers require elevation.
package scheduler
