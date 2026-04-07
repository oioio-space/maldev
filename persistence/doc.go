// Package persistence provides system persistence techniques for maintaining
// access across reboots.
//
// Sub-packages implement specific persistence mechanisms:
//   - registry: Run/RunOnce key persistence (Windows)
//   - startup: StartUp folder LNK shortcut persistence (Windows)
//   - scheduler: Task Scheduler persistence via schtasks.exe (Windows)
package persistence
