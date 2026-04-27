//go:build windows

package clr_test

import (
	"fmt"

	"github.com/oioio-space/maldev/runtime/clr"
)

// InstalledRuntimes lists every CLR version present on the host.
// Useful for picking a version Load() will accept.
func ExampleInstalledRuntimes() {
	runtimes, err := clr.InstalledRuntimes()
	if err != nil {
		fmt.Println("enum:", err)
		return
	}
	for _, r := range runtimes {
		fmt.Println(r)
	}
}

// InstallRuntimeActivationPolicy drops the <exe>.config side-by-side
// file that enables legacy v2 activation. Call before Runtime.Load.
// Pair with RemoveRuntimeActivationPolicy on the way out.
func ExampleInstallRuntimeActivationPolicy() {
	if err := clr.InstallRuntimeActivationPolicy(); err != nil {
		fmt.Println("install:", err)
		return
	}
	defer clr.RemoveRuntimeActivationPolicy()
	// ... clr.Load(...) and clr.ExecuteAssembly(...) here
}
