//go:build windows

package service_test

import (
	"fmt"

	"github.com/oioio-space/maldev/persistence/service"
)

// Install creates a SCM record that auto-starts the binary at boot.
func ExampleInstall() {
	cfg := &service.Config{
		Name:      "MySvc",
		BinPath:   `C:\Path\to\impl.exe`,
		StartType: service.StartAuto,
	}
	if err := service.Install(cfg); err != nil {
		fmt.Println("install:", err)
	}
}

// Start / Stop / IsRunning / Uninstall cover the lifecycle.
func ExampleStart() {
	_ = service.Start("MySvc")
	if service.IsRunning("MySvc") {
		fmt.Println("running")
	}
	_ = service.Stop("MySvc")
}
