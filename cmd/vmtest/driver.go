package main

import (
	"context"
	"fmt"
)

// Driver abstracts a hypervisor. Two implementations ship:
//   - vbox     — VBoxManage (guestcontrol + shared folder)
//   - libvirt  — virsh + ssh + rsync/scp
//
// The test runner orchestrates a driver through a fixed sequence:
//
//	Start → WaitReady → Push → Exec → (deferred) Stop → Restore
type Driver interface {
	Name() string

	Start(ctx context.Context, vm *VMConfig) error
	WaitReady(ctx context.Context, vm *VMConfig) error
	Stop(ctx context.Context, vm *VMConfig) error
	Restore(ctx context.Context, vm *VMConfig) error

	// Push copies the host project tree into the guest. No-op when the
	// driver uses a live shared folder (VBox).
	Push(ctx context.Context, vm *VMConfig, hostRoot string) error

	// Exec runs go test inside the guest and returns the test exit code.
	// The error is only non-nil when the orchestration itself failed
	// (SSH dropped, guestcontrol crashed); a failing test returns exit≠0
	// with err=nil.
	Exec(ctx context.Context, vm *VMConfig, packages, flags string) (int, error)
}

// SelectDriver constructs the configured driver.
func SelectDriver(cfg *Config) (Driver, error) {
	switch cfg.Driver {
	case "vbox":
		return NewVBoxDriver(cfg)
	case "libvirt":
		return NewLibvirtDriver(cfg)
	default:
		return nil, fmt.Errorf("unknown driver %q (want vbox or libvirt)", cfg.Driver)
	}
}
