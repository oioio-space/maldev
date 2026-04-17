package main

import (
	"context"
	"fmt"
)

// RunVM orchestrates a full VM test cycle: start, wait-ready, push source,
// exec tests, stop, restore snapshot. Stop+Restore run regardless of earlier
// failures so the VM always returns to its INIT state for the next run.
func RunVM(ctx context.Context, drv Driver, vm *VMConfig, hostRoot, packages, flags string) int {
	label := vmLabel(drv, vm)
	fmt.Printf("=== VM: %s ===\n", label)

	if err := drv.Start(ctx, vm); err != nil {
		fmt.Printf("start failed: %v\n", err)
		return 1
	}
	defer func() {
		if err := drv.Stop(ctx, vm); err != nil {
			fmt.Printf("stop: %v\n", err)
		}
		if err := drv.Restore(ctx, vm); err != nil {
			fmt.Printf("restore snapshot %q: %v\n", vm.Snapshot, err)
		}
	}()

	if err := drv.WaitReady(ctx, vm); err != nil {
		fmt.Printf("wait-ready failed: %v\n", err)
		return 1
	}
	if err := drv.Push(ctx, vm, hostRoot); err != nil {
		fmt.Printf("push failed: %v\n", err)
		return 1
	}

	fmt.Printf("Running tests: go test %s %s\n", packages, flags)
	code, err := drv.Exec(ctx, vm, packages, flags)
	if err != nil {
		fmt.Printf("exec failed: %v\n", err)
		return 1
	}
	fmt.Printf("=== %s: exit code %d ===\n", label, code)
	return code
}

func vmLabel(drv Driver, vm *VMConfig) string {
	switch drv.Name() {
	case "vbox":
		return vm.VBoxName
	case "libvirt":
		return vm.LibvirtName
	}
	if vm.VBoxName != "" {
		return vm.VBoxName
	}
	return vm.LibvirtName
}
