// Package scheduler provides Windows Task Scheduler persistence via schtasks.exe.
//
// Technique: Windows Task Scheduler persistence via schtasks.exe.
// MITRE ATT&CK: T1053.005 (Scheduled Task/Job: Scheduled Task)
// Platform: Windows
// Detection: Medium -- Scheduled tasks are logged and monitored.
//
// How it works: Invokes schtasks.exe to create, query, and delete scheduled
// tasks. The console window is hidden via SysProcAttr to avoid visible
// artifacts. Supports logon, startup, and daily triggers.
//
// Task names may include backslash-separated folder paths (e.g.,
// "Microsoft\Windows\MyTask") to organize tasks within the Task Scheduler
// namespace.
//
// Startup-triggered tasks (TriggerStartup) require elevated privileges.
package scheduler
