//go:build windows

package registry_test

import (
	"fmt"

	"github.com/oioio-space/maldev/persistence/registry"
)

// Set writes the named value under HKCU\...\Run.
func ExampleSet() {
	if err := registry.Set(registry.HiveCurrentUser, registry.KeyRun,
		"Updater", `C:\Users\Public\u.exe`); err != nil {
		fmt.Println("set:", err)
	}
}

// Exists / Get / Delete cover the lifecycle.
func ExampleDelete() {
	_ = registry.Delete(registry.HiveCurrentUser, registry.KeyRun, "Updater")
}

// RunKeyMechanism adapts the package to persistence.InstallAll.
func ExampleRunKeyMechanism() {
	mech := registry.RunKey(registry.HiveCurrentUser, registry.KeyRun,
		"MyApp", `C:\Path\to\bin.exe`)
	if err := mech.Install(); err != nil {
		fmt.Println("install:", err)
	}
}
