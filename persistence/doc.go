// Package persistence provides system persistence techniques for maintaining
// access across reboots.
//
// The Mechanism interface enables composable, redundant persistence:
//
//	mechanisms := []persistence.Mechanism{
//	    registry.RunKey(registry.HiveCurrentUser, registry.KeyRun, "MyApp", binPath),
//	    startup.Shortcut("MyApp", binPath, ""),
//	    scheduler.ScheduledTask(`\MyTask`, scheduler.WithAction(binPath), scheduler.WithTriggerLogon()),
//	    service.Service(&service.Config{Name: "MySvc", BinPath: binPath, StartType: service.StartAuto}),
//	}
//	errs := persistence.InstallAll(mechanisms)
//
// Each sub-package also exposes standalone functions for direct use.
//
// Sub-packages:
//   - registry: Run/RunOnce key persistence (Windows)
//   - startup: StartUp folder LNK shortcut persistence (Windows)
//   - scheduler: Task Scheduler persistence via COM ITaskService (Windows)
//   - service: Windows service persistence via SCM (Windows)
package persistence
