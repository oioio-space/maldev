//go:build windows

package service_test

import (
	"fmt"

	"github.com/oioio-space/maldev/cleanup/service"
)

// HideService applies a restrictive DACL on a service so it stops
// appearing in services.msc / sc query / Get-Service for non-SYSTEM
// callers.
func ExampleHideService() {
	out, err := service.HideService(service.Native, "", "MyService")
	if err != nil {
		fmt.Println("hide failed:", err, out)
		return
	}
	fmt.Println("hidden")
}

// UnHideService restores the default DACL.
func ExampleUnHideService() {
	if _, err := service.UnHideService(service.Native, "", "MyService"); err != nil {
		fmt.Println("unhide failed:", err)
	}
}
