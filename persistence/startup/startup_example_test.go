//go:build windows

package startup_test

import (
	"fmt"

	"github.com/oioio-space/maldev/persistence/startup"
)

// Install drops a .lnk in the per-user Startup folder. No elevation.
func ExampleInstall() {
	if err := startup.Install("Updater", `C:\Users\Public\u.exe`, ""); err != nil {
		fmt.Println("install:", err)
	}
}

// InstallMachine targets the all-users Startup folder. Requires admin.
func ExampleInstallMachine() {
	_ = startup.InstallMachine("Updater", `C:\ProgramData\u.exe`, "")
}

// Remove deletes the per-user shortcut by name.
func ExampleRemove() {
	_ = startup.Remove("Updater")
}
