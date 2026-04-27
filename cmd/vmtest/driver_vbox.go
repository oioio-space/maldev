package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

// Hypervisor lifecycle (VBoxManage). Intra-VM ops below use SSH so the same
// driver works around the VBox 7.2 guestcontrol bugs (whitespace truncation in
// `-Flags`, `--target-directory` rejection on existing dirs, transient share
// kernel "Protocol error") and matches the libvirt driver's paradigm.

func (d *vboxDriver) Start(ctx context.Context, vm *VMConfig) error {
	fmt.Printf("Starting VBox VM %s...\n", vm.VBoxName)
	return d.run(ctx, "startvm", vm.VBoxName, "--type", "headless")
}

// WaitReady resolves the guest IP via Guest Additions properties (host-only
// adapter, NAT range filtered out), then polls SSH until reachable. The IP is
// cached on vm.SSHHost so subsequent Push/Exec/Fetch reuse it.
func (d *vboxDriver) WaitReady(ctx context.Context, vm *VMConfig) error {
	port := sshPort(vm)
	deadline := waitReadyDeadline(vm)
	fmt.Printf("Waiting up to %s for SSH on %s...\n", deadline, vm.VBoxName)
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SSH on %s", vm.VBoxName)
		default:
		}
		host := vm.SSHHost
		if host == "" {
			host = d.discoverIP(ctx, vm.VBoxName)
		}
		if host != "" && tryDial(host, port, 2*time.Second) {
			vm.SSHHost = host
			fmt.Printf("SSH reachable at %s:%d\n", host, port)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SSH on %s", vm.VBoxName)
		case <-time.After(3 * time.Second):
		}
	}
}

// discoverIP walks /VirtualBox/GuestInfo/Net/<n>/V4/IP guest properties and
// returns the first address that isn't on the NAT 10.0.x.x range. The
// host-only adapter typically lives at index 1 (after NAT at index 0).
func (d *vboxDriver) discoverIP(ctx context.Context, vmName string) string {
	for i := 0; i < 8; i++ {
		out, err := exec.CommandContext(ctx, d.exe, "guestproperty", "get", vmName,
			fmt.Sprintf("/VirtualBox/GuestInfo/Net/%d/V4/IP", i)).Output()
		if err != nil {
			continue
		}
		ip := parseGuestPropertyValue(out)
		if ip == "" || strings.HasPrefix(ip, "10.0.") {
			continue
		}
		return ip
	}
	return ""
}

// parseGuestPropertyValue extracts "x" from `Value: x` output of
// `VBoxManage guestproperty get`. Returns "" for "No value set!".
func parseGuestPropertyValue(out []byte) string {
	s := strings.TrimSpace(string(out))
	const prefix = "Value:"
	if !strings.HasPrefix(s, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(s, prefix))
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

// Push synchronises hostRoot into the guest via tar piped over ssh. Cross-
// platform: works from any host with tar+ssh (Git Bash on Windows ships both)
// to any guest with tar (Linux ships it; Windows 10+ ships it via System32).
func (d *vboxDriver) Push(ctx context.Context, vm *VMConfig, hostRoot string) error {
	key, err := resolveSSHKey(vm)
	if err != nil {
		return err
	}
	if vm.SSHHost == "" {
		return errors.New("vbox Push: no ssh_host (WaitReady must run first)")
	}
	dst := vm.ProjectCopyPath
	if dst == "" {
		if vm.Platform == "windows" {
			dst = `C:\maldev`
		} else {
			dst = "/tmp/maldev"
		}
	}
	return pushTar(ctx, vm, hostRoot, dst, key, sshPort(vm))
}

// pushTar streams `tar -czf - …` from the host into `tar -xzf - -C dst` on the
// guest over an SSH pipe. Avoids the rsync dependency (not available in Git
// Bash on Windows hosts) and the VBox shared-folder kernel races.
func pushTar(ctx context.Context, vm *VMConfig, hostRoot, dst, key string, port int) error {
	if err := sshRun(ctx, vm, key, port, remoteCleanCmd(vm.Platform, dst)); err != nil {
		return fmt.Errorf("clean %s on guest: %w", dst, err)
	}

	tarSrc := exec.CommandContext(ctx, "tar",
		"-czf", "-",
		"--exclude=.git",
		"--exclude=ignore",
		"--exclude=.claude",
		"--exclude=.idea",
		"--exclude=.vscode",
		"--exclude=logs",
		"-C", hostRoot, ".",
	)
	tarSrc.Stderr = os.Stderr

	sshArgs := []string{
		"-i", key, "-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", vm.User, vm.SSHHost),
		remoteExtractCmd(vm.Platform, dst),
	}
	sshDst := exec.CommandContext(ctx, "ssh", sshArgs...)
	sshDst.Stderr = os.Stderr

	pipe, err := tarSrc.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	sshDst.Stdin = pipe

	if err := sshDst.Start(); err != nil {
		return fmt.Errorf("start ssh: %w", err)
	}
	if err := tarSrc.Run(); err != nil {
		_ = sshDst.Wait()
		return fmt.Errorf("tar source: %w", err)
	}
	if err := sshDst.Wait(); err != nil {
		return fmt.Errorf("ssh extract: %w", err)
	}
	return nil
}

// remoteCleanCmd returns a one-liner that wipes and recreates dst inside the
// guest, parameterised on guest OS.
func remoteCleanCmd(platform, dst string) string {
	if platform == "windows" {
		return fmt.Sprintf(`cmd.exe /c "if exist %s rmdir /s /q %s & mkdir %s"`, dst, dst, dst)
	}
	return fmt.Sprintf("rm -rf %s && mkdir -p %s", dst, dst)
}

// remoteExtractCmd returns the tar-extract command run inside the guest as the
// destination of the ssh-piped tar stream.
func remoteExtractCmd(platform, dst string) string {
	if platform == "windows" {
		// tar.exe ships in System32 since Windows 10 1803.
		return fmt.Sprintf(`tar -xzf - -C %s`, dst)
	}
	return fmt.Sprintf("tar -xzf - -C %s", dst)
}

// Exec runs `go test` inside the guest over ssh.
func (d *vboxDriver) Exec(ctx context.Context, vm *VMConfig, packages, flags string, logWriter io.Writer) (int, error) {
	key, err := resolveSSHKey(vm)
	if err != nil {
		return 1, err
	}
	if vm.SSHHost == "" {
		return 1, errors.New("vbox Exec: no ssh_host (WaitReady must run first)")
	}
	dst := vm.ProjectCopyPath
	if dst == "" {
		if vm.Platform == "windows" {
			dst = `C:\maldev`
		} else {
			dst = "/tmp/maldev"
		}
	}
	remote, err := remoteGoTest(vm.Platform, dst, packages, flags, collectMaldevEnv())
	if err != nil {
		return 1, err
	}
	args := []string{
		"-i", key, "-p", strconv.Itoa(sshPort(vm)),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", vm.User, vm.SSHHost),
		remote,
	}
	return runCapturingExit(ctx, "ssh", args, logWriter)
}

// remoteGoTest builds the cd+env+go-test command line for the guest. envs is
// the slice returned by collectMaldevEnv() ("KEY=VALUE" entries).
func remoteGoTest(platform, dst, packages, flags string, envs []string) (string, error) {
	switch platform {
	case "windows":
		var setCmds bytes.Buffer
		for _, kv := range envs {
			fmt.Fprintf(&setCmds, "set %s&& ", kv)
		}
		return fmt.Sprintf(`cmd.exe /c "cd /d %s && %sgo test %s %s"`, dst, setCmds.String(), packages, flags), nil
	case "linux":
		envPrefix := strings.Join(envs, " ")
		if envPrefix != "" {
			envPrefix += " "
		}
		return fmt.Sprintf("cd %s && %sgo test %s %s", dst, envPrefix, packages, flags), nil
	default:
		return "", fmt.Errorf("vbox Exec: unsupported platform %q", platform)
	}
}

// Fetch pulls a single file from the guest back to the host via scp.
func (d *vboxDriver) Fetch(ctx context.Context, vm *VMConfig, guestPath, hostPath string) error {
	key, err := resolveSSHKey(vm)
	if err != nil {
		return err
	}
	if vm.SSHHost == "" {
		return errors.New("vbox Fetch: no ssh_host (WaitReady must run first)")
	}
	if err := os.MkdirAll(filepath.Dir(hostPath), 0o755); err != nil {
		return fmt.Errorf("mkdir host dir: %w", err)
	}
	src := fmt.Sprintf("%s@%s:%s", vm.User, vm.SSHHost, guestPath)
	args := []string{
		"-i", key, "-P", strconv.Itoa(sshPort(vm)),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		src, hostPath,
	}
	cmd := exec.CommandContext(ctx, "scp", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runCapturingExit executes a command with stdout/stderr passthrough and
// returns the exit code separately from the error: a non-zero exit is not an
// orchestration failure — we want to keep running teardown. When logWriter is
// non-nil it receives the same bytes as os.Stdout/os.Stderr so callers can
// persist a test.log file alongside the live console stream.
func runCapturingExit(ctx context.Context, exe string, args []string, logWriter io.Writer) (int, error) {
	cmd := exec.CommandContext(ctx, exe, args...)
	if logWriter != nil {
		cmd.Stdout = io.MultiWriter(os.Stdout, logWriter)
		cmd.Stderr = io.MultiWriter(os.Stderr, logWriter)
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
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
