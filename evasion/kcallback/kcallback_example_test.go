//go:build windows

package kcallback_test

import (
	"fmt"

	"github.com/oioio-space/maldev/evasion/kcallback"
)

// NtoskrnlBase resolves the kernel image base via SystemModuleInformation.
// Requires SeDebugPrivilege.
func ExampleNtoskrnlBase() {
	base, err := kcallback.NtoskrnlBase()
	if err != nil {
		fmt.Println("base:", err)
		return
	}
	fmt.Printf("ntoskrnl base: 0x%x\n", base)
}

// DriverAt resolves a callback-array address to its hosting driver
// name. Useful for "which EDR registered this callback?" introspection.
func ExampleDriverAt() {
	addr := uintptr(0xfffff80012345678) // example callback slot
	driver, err := kcallback.DriverAt(addr)
	if err != nil {
		fmt.Println("lookup:", err)
		return
	}
	fmt.Println(driver)
}
