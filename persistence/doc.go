// Package persistence is the umbrella for system persistence
// techniques — mechanisms that re-launch an implant across
// reboots and user logons.
//
// The [Mechanism] interface is the composition primitive: each
// sub-package returns a `Mechanism` (or several), and
// [InstallAll] / [VerifyAll] / [UninstallAll] operate on a flat
// slice. Operators typically install two or three mechanisms in
// parallel — Run key + scheduled task + service — so failure of
// any single one does not lose persistence.
//
//	mechanisms := []persistence.Mechanism{
//	    registry.RunKey(registry.HiveCurrentUser, registry.KeyRun, "MyApp", binPath),
//	    startup.Shortcut("MyApp", binPath, ""),
//	    scheduler.ScheduledTask(`\MyTask`,
//	        scheduler.WithAction(binPath),
//	        scheduler.WithTriggerLogon()),
//	    service.Service(&service.Config{
//	        Name: "MySvc", BinPath: binPath, StartType: service.StartAuto,
//	    }),
//	}
//	errs := persistence.InstallAll(mechanisms)
//
// Each sub-package also exposes standalone install / uninstall
// functions for direct use.
//
// Sub-packages:
//
//   - persistence/registry — Run / RunOnce key persistence (HKCU + HKLM).
//   - persistence/startup — StartUp-folder LNK shortcut persistence.
//   - persistence/scheduler — Task Scheduler via COM ITaskService.
//   - persistence/service — Windows service via SCM.
//   - persistence/lnk — LNK shortcut creation primitive (used by startup).
//   - persistence/account — local user account add / delete / group membership.
//
// # MITRE ATT&CK
//
//   - T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) — registry, startup
//   - T1547.009 (Shortcut Modification) — lnk, startup
//   - T1053.005 (Scheduled Task/Job: Scheduled Task) — scheduler
//   - T1543.003 (Create or Modify System Process: Windows Service) — service
//   - T1136.001 (Create Account: Local Account) — account
//   - T1204.002 (User Execution: Malicious File) — lnk
//
// # Detection level
//
// Varies by sub-package. Run-key + StartUp-folder are commonly
// monitored; scheduled tasks via COM evade `schtasks.exe`-spawn
// telemetry; SCM-installed services light up Sysmon Event 7045
// and Security Event 4697; local-account creation generates
// 4720 / 4732. Each sub-package documents its own detection
// level.
//
// # Example
//
// See [github.com/oioio-space/maldev/persistence/registry],
// [github.com/oioio-space/maldev/persistence/scheduler], and
// the umbrella [InstallAll] / [VerifyAll] / [UninstallAll]
// helpers for runnable composition.
//
// # See also
//
//   - docs/techniques/persistence/README.md
//   - [github.com/oioio-space/maldev/cleanup] — wipe persistence artefacts post-op
//   - [github.com/oioio-space/maldev/privesc] — pair with privesc to install HKLM / SYSTEM-scope mechanisms
//
// [github.com/oioio-space/maldev/persistence/registry]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/registry
// [github.com/oioio-space/maldev/persistence/scheduler]: https://pkg.go.dev/github.com/oioio-space/maldev/persistence/scheduler
// [github.com/oioio-space/maldev/cleanup]: https://pkg.go.dev/github.com/oioio-space/maldev/cleanup
// [github.com/oioio-space/maldev/privesc]: https://pkg.go.dev/github.com/oioio-space/maldev/privesc
package persistence
