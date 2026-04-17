package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type vboxDriver struct {
	exe string
}

// NewVBoxDriver resolves VBoxManage from config, PATH, or a well-known
// Windows install path, in that order.
func NewVBoxDriver(cfg *Config) (Driver, error) {
	exe := cfg.VBox.ExePath
	if exe == "" {
		if p, err := exec.LookPath("VBoxManage"); err == nil {
			exe = p
		} else if p, err := exec.LookPath("VBoxManage.exe"); err == nil {
			exe = p
		}
	}
	if exe == "" && runtime.GOOS == "windows" {
		exe = `C:/Program Files/Oracle/VirtualBox/VBoxManage.exe`
	}
	if exe == "" {
		return nil, errors.New("VBoxManage not found in PATH or config.vbox.exe_path")
	}
	return &vboxDriver{exe: exe}, nil
}

func (d *vboxDriver) Name() string { return "vbox" }

func (d *vboxDriver) run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, d.exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (d *vboxDriver) Start(ctx context.Context, vm *VMConfig) error {
	fmt.Printf("Starting VBox VM %s...\n", vm.VBoxName)
	return d.run(ctx, "startvm", vm.VBoxName, "--type", "headless")
}

func (d *vboxDriver) WaitReady(ctx context.Context, vm *VMConfig) error {
	secs := vm.WaitReadySeconds
	if secs <= 0 {
		secs = 45
	}
	fmt.Printf("Waiting %ds for Guest Additions...\n", secs)
	select {
	case <-time.After(time.Duration(secs) * time.Second):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *vboxDriver) Stop(ctx context.Context, vm *VMConfig) error {
	fmt.Printf("Stopping VBox VM %s...\n", vm.VBoxName)
	// poweroff can fail if the VM is already down — swallow.
	cmd := exec.CommandContext(ctx, d.exe, "controlvm", vm.VBoxName, "poweroff")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	time.Sleep(3 * time.Second)
	return nil
}

func (d *vboxDriver) Restore(ctx context.Context, vm *VMConfig) error {
	fmt.Printf("Restoring snapshot %s on %s...\n", vm.Snapshot, vm.VBoxName)
	return d.run(ctx, "snapshot", vm.VBoxName, "restore", vm.Snapshot)
}

// Push for VBox: the Windows VM has a persistent shared folder configured at
// VM-creation time; Linux VMs need a transient share added per run because
// snapshot-restore drops transient definitions. hostRoot is the repo root on
// the host.
func (d *vboxDriver) Push(ctx context.Context, vm *VMConfig, hostRoot string) error {
	if vm.Platform != "linux" || vm.SharedFolder == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, d.exe,
		"sharedfolder", "add", vm.VBoxName,
		"--name", vm.SharedFolder,
		"--hostpath", hostRoot,
		"--automount", "--transient")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// Non-fatal: the share may already be attached from a prior session.
	_ = cmd.Run()
	return nil
}

func (d *vboxDriver) Exec(ctx context.Context, vm *VMConfig, packages, flags string) (int, error) {
	switch vm.Platform {
	case "windows":
		return d.execWindows(ctx, vm, packages, flags)
	case "linux":
		return d.execLinux(ctx, vm, packages, flags)
	default:
		return 1, fmt.Errorf("vbox: unsupported platform %q", vm.Platform)
	}
}

func (d *vboxDriver) execWindows(ctx context.Context, vm *VMConfig, packages, flags string) (int, error) {
	runner := vm.GuestRunner
	if runner == "" {
		runner = `Z:\scripts\vm-test.ps1`
	}
	args := []string{
		"guestcontrol", vm.VBoxName, "run",
		"--exe", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"--username", vm.User,
		"--password", vm.Password,
		"--wait-stdout", "--wait-stderr",
	}
	// Forward host MALDEV_* env vars via VBoxManage --putenv so gated tests
	// (MALDEV_INTRUSIVE, MALDEV_MANUAL) propagate into the guest process.
	for _, kv := range collectMaldevEnv() {
		args = append(args, "--putenv", kv)
	}
	args = append(args,
		"--", "powershell.exe",
		"-ExecutionPolicy", "Bypass",
		"-File", runner,
		"-Packages", packages,
		"-Flags", flags,
	)
	return runCapturingExit(ctx, d.exe, args)
}

func (d *vboxDriver) execLinux(ctx context.Context, vm *VMConfig, packages, flags string) (int, error) {
	dst := vm.ProjectCopyPath
	if dst == "" {
		dst = "/tmp/maldev"
	}
	share := vm.SharedFolder
	if share == "" {
		share = "maldev"
	}
	envs := collectMaldevEnv()
	envPrefix := strings.Join(envs, " ")
	if envPrefix != "" {
		envPrefix += " "
	}
	// Try the kernel auto-mount path first (/media/sf_<share>), fall back to
	// the user-specified mount. Matches the legacy vm-run-tests.sh behaviour.
	script := fmt.Sprintf(
		"cp -r /media/sf_%s %s 2>/dev/null || cp -r /mnt/%s %s; "+
			"cd %s; "+
			"%sgo test %s %s 2>&1; "+
			"echo VM_TEST_EXIT_CODE=$?",
		share, dst, share, dst, dst, envPrefix, packages, flags,
	)
	args := []string{
		"guestcontrol", vm.VBoxName, "run",
		"--exe", "/bin/bash",
		"--username", vm.User,
		"--password", vm.Password,
		"--wait-stdout", "--wait-stderr",
		"--", "bash", "-c", script,
	}
	return runCapturingExit(ctx, d.exe, args)
}

// runCapturingExit executes a command with stdout/stderr passthrough and
// returns the exit code separately from the error: a non-zero exit is not an
// orchestration failure — we want to keep running teardown.
func runCapturingExit(ctx context.Context, exe string, args []string) (int, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 1, err
}
