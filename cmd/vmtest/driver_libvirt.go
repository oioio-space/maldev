package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type libvirtDriver struct {
	uri string
}

// NewLibvirtDriver verifies virsh is installed and captures the libvirt URI.
// Default URI is qemu:///system (host-wide VMs); qemu:///session is used for
// per-user VMs (no root required but limited network options).
func NewLibvirtDriver(cfg *Config) (Driver, error) {
	if _, err := exec.LookPath("virsh"); err != nil {
		return nil, errors.New("virsh not found — install libvirt-client")
	}
	uri := cfg.Libvirt.ConnectURI
	if uri == "" {
		uri = "qemu:///system"
	}
	return &libvirtDriver{uri: uri}, nil
}

func (d *libvirtDriver) Name() string { return "libvirt" }

// virshEnv runs virsh with LC_ALL=C so output strings (domstate, domifaddr)
// stay in English — parsing them against literal "running" / "ipv4" fails
// otherwise on a French-locale host.
func (d *libvirtDriver) virshEnv() []string {
	return append(os.Environ(), "LC_ALL=C", "LANG=C")
}

func (d *libvirtDriver) virsh(ctx context.Context, args ...string) error {
	full := append([]string{"-c", d.uri}, args...)
	cmd := exec.CommandContext(ctx, "virsh", full...)
	cmd.Env = d.virshEnv()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (d *libvirtDriver) virshCapture(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{"-c", d.uri}, args...)
	cmd := exec.CommandContext(ctx, "virsh", full...)
	cmd.Env = d.virshEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}

func (d *libvirtDriver) Start(ctx context.Context, vm *VMConfig) error {
	name := vm.LibvirtName
	if name == "" {
		return fmt.Errorf("libvirt: empty libvirt_name (set in config.local.yaml)")
	}
	// Skip start if already running — avoids virsh error.
	if out, err := d.virshCapture(ctx, "domstate", name); err == nil {
		if strings.TrimSpace(string(out)) == "running" {
			fmt.Printf("libvirt VM %s already running\n", name)
			return nil
		}
	}
	fmt.Printf("Starting libvirt VM %s...\n", name)
	return d.virsh(ctx, "start", name)
}

// WaitReady resolves the guest IP (via DHCP lease, qemu-guest-agent, or ARP),
// then polls TCP connect on the SSH port until it succeeds or the overall
// deadline expires. The resolved IP is cached in vm.SSHHost for Push/Exec.
func (d *libvirtDriver) WaitReady(ctx context.Context, vm *VMConfig) error {
	port := sshPort(vm)
	deadline := waitReadyDeadline(vm)
	fmt.Printf("Waiting up to %s for SSH on %s...\n", deadline, vm.LibvirtName)
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SSH on %s", vm.LibvirtName)
		default:
		}
		host := vm.SSHHost
		if host == "" {
			host = d.discoverIP(ctx, vm.LibvirtName)
		}
		if host != "" && tryDial(host, port, 2*time.Second) {
			vm.SSHHost = host
			fmt.Printf("SSH reachable at %s:%d\n", host, port)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for SSH on %s", vm.LibvirtName)
		case <-time.After(3 * time.Second):
		}
	}
}

func waitReadyDeadline(vm *VMConfig) time.Duration {
	secs := vm.WaitReadySeconds
	if secs <= 0 {
		secs = 120
	}
	// Allow generous headroom for snapshot-reverted VMs finishing boot.
	if secs < 180 {
		secs = 180
	}
	return time.Duration(secs) * time.Second
}

// discoverIP tries lease > agent > ARP. Lease works when the VM is on a
// libvirt-managed network (virbr0). agent needs qemu-guest-agent in the
// guest. ARP is the last-resort fallback.
func (d *libvirtDriver) discoverIP(ctx context.Context, name string) string {
	for _, src := range []string{"lease", "agent", "arp"} {
		out, err := d.virshCapture(ctx, "domifaddr", name, "--source", src)
		if err != nil {
			continue
		}
		if ip := parseDomIfAddr(out); ip != "" {
			return ip
		}
	}
	return ""
}

// parseDomIfAddr extracts the first non-loopback IPv4 from `virsh domifaddr`.
//
// Format:
//
//	Name       MAC address          Protocol     Address
//	-----------------------------------------------------------
//	vnet0      52:54:00:xx:xx:xx    ipv4         192.168.122.42/24
func parseDomIfAddr(out []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "ipv4") {
			continue
		}
		for _, f := range strings.Fields(line) {
			if slash := strings.IndexByte(f, '/'); slash > 0 {
				f = f[:slash]
			}
			ip := net.ParseIP(f)
			if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}

func tryDial(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (d *libvirtDriver) Stop(ctx context.Context, vm *VMConfig) error {
	name := vm.LibvirtName
	fmt.Printf("Stopping libvirt VM %s...\n", name)
	cmd := exec.CommandContext(ctx, "virsh", "-c", d.uri, "destroy", name)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
	time.Sleep(2 * time.Second)
	return nil
}

func (d *libvirtDriver) Restore(ctx context.Context, vm *VMConfig) error {
	return d.virsh(ctx, "snapshot-revert", vm.LibvirtName, "--snapshotname", vm.Snapshot, "--force")
}

func (d *libvirtDriver) Push(ctx context.Context, vm *VMConfig, hostRoot string) error {
	key, err := resolveSSHKey(vm)
	if err != nil {
		return err
	}
	if vm.SSHHost == "" {
		return errors.New("libvirt Push: no ssh_host (WaitReady must run first)")
	}
	dst := vm.ProjectCopyPath
	if dst == "" {
		if vm.Platform == "windows" {
			dst = `C:\maldev`
		} else {
			dst = "/tmp/maldev"
		}
	}
	port := sshPort(vm)
	switch vm.Platform {
	case "linux":
		return pushLinux(ctx, vm, hostRoot, dst, key, port)
	case "windows":
		return pushWindows(ctx, vm, hostRoot, dst, key, port)
	default:
		return fmt.Errorf("libvirt Push: unsupported platform %q", vm.Platform)
	}
}

func pushLinux(ctx context.Context, vm *VMConfig, hostRoot, dst, key string, port int) error {
	src := filepath.Clean(hostRoot) + "/"
	sshCmd := fmt.Sprintf(
		"ssh -i %s -p %d -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes",
		shellQuote(key), port,
	)
	target := fmt.Sprintf("%s@%s:%s", vm.User, vm.SSHHost, dst)
	// rsync excludes mirror the committed vm-exclude.txt plus local-only dirs.
	args := []string{
		"-az", "--delete",
		"--exclude", ".git",
		"--exclude", "ignore",
		"--exclude", ".claude",
		"--exclude", ".idea",
		"--exclude", ".vscode",
		"--exclude", "bin/",
		"--exclude", "dist/",
		"-e", sshCmd,
		src, target,
	}
	cmd := exec.CommandContext(ctx, "rsync", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// pushWindows uses scp because rsync over Windows OpenSSH is not universally
// available. We wipe the destination before copying to keep snapshot
// isolation (each run starts from a clean tree).
func pushWindows(ctx context.Context, vm *VMConfig, hostRoot, dst, key string, port int) error {
	// Clean destination via ssh + cmd.exe. rmdir /s /q is a no-op if absent.
	cleanCmd := fmt.Sprintf(`cmd.exe /c "if exist %s rmdir /s /q %s && mkdir %s"`, dst, dst, dst)
	if err := sshRun(ctx, vm, key, port, cleanCmd); err != nil {
		fmt.Printf("warn: pre-push clean failed: %v\n", err)
	}
	winDst := strings.ReplaceAll(dst, "\\", "/")
	target := fmt.Sprintf("%s@%s:%s", vm.User, vm.SSHHost, winDst)
	args := []string{
		"-i", key, "-P", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-r", filepath.Clean(hostRoot) + string(filepath.Separator) + ".", target,
	}
	cmd := exec.CommandContext(ctx, "scp", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func sshRun(ctx context.Context, vm *VMConfig, key string, port int, remoteCmd string) error {
	args := []string{
		"-i", key, "-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", vm.User, vm.SSHHost),
		remoteCmd,
	}
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (d *libvirtDriver) Exec(ctx context.Context, vm *VMConfig, packages, flags string) (int, error) {
	key, err := resolveSSHKey(vm)
	if err != nil {
		return 1, err
	}
	port := sshPort(vm)
	dst := vm.ProjectCopyPath
	if dst == "" {
		if vm.Platform == "windows" {
			dst = `C:\maldev`
		} else {
			dst = "/tmp/maldev"
		}
	}
	envs := collectMaldevEnv()
	var remote string
	switch vm.Platform {
	case "windows":
		// cmd.exe: set each env var then && go test. Quotes kept minimal so the
		// outer `cmd.exe /c "..."` parses unambiguously.
		setCmds := ""
		for _, kv := range envs {
			setCmds += "set " + kv + "&& "
		}
		remote = fmt.Sprintf(`cmd.exe /c "cd /d %s && %sgo test %s %s"`, dst, setCmds, packages, flags)
	case "linux":
		envPrefix := strings.Join(envs, " ")
		if envPrefix != "" {
			envPrefix += " "
		}
		remote = fmt.Sprintf("cd %s && %sgo test %s %s", dst, envPrefix, packages, flags)
	default:
		return 1, fmt.Errorf("libvirt Exec: unsupported platform %q", vm.Platform)
	}
	args := []string{
		"-i", key, "-p", strconv.Itoa(port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		fmt.Sprintf("%s@%s", vm.User, vm.SSHHost),
		remote,
	}
	return runCapturingExit(ctx, "ssh", args)
}

// collectMaldevEnv scans the host environment for MALDEV_* variables and
// returns them as "KEY=VALUE" strings ready to prefix a go test command.
// Lets operators set `MALDEV_INTRUSIVE=1 MALDEV_MANUAL=1 ./scripts/vm-run-tests.sh ...`
// and have the gates propagate into the guest.
func collectMaldevEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "MALDEV_") {
			out = append(out, kv)
		}
	}
	return out
}

func sshPort(vm *VMConfig) int {
	if vm.SSHPort > 0 {
		return vm.SSHPort
	}
	return 22
}

// resolveSSHKey prefers the explicit config value, else defaults to
// ~/.ssh/vm_<platform>_key, expands a leading ~/ and verifies the file exists.
func resolveSSHKey(vm *VMConfig) (string, error) {
	key := vm.SSHKey
	if key == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("ssh key default: %w", err)
		}
		key = filepath.Join(home, ".ssh", "vm_"+vm.Platform+"_key")
	}
	if strings.HasPrefix(key, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand ~: %w", err)
		}
		key = filepath.Join(home, key[2:])
	}
	if _, err := os.Stat(key); err != nil {
		return "", fmt.Errorf("ssh key %s: %w", key, err)
	}
	return key, nil
}

// shellQuote wraps a path in double quotes if it contains spaces — adequate
// for the -e argument to rsync which is re-split by rsync's own parser.
func shellQuote(s string) string {
	if !strings.ContainsAny(s, " \t") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
