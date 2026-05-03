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
	"regexp"
	"strconv"
	"strings"

	"github.com/oioio-space/maldev/encode"
)

// Constants shared between host orchestration and the guest scripts. The
// password is fixed and known to both: INIT snapshots wipe the lowuser
// account, so confidentiality has no value here.
const (
	guestWorkDir = `C:\Users\Public\maldev`
	guestToolDir = `C:\maldev-tools`
	lowUser      = "lowuser"
	lowPassword  = "MaldevLow42!Throwaway"
)

// RunBinaryOpts drives the -bin mode: cross-build a Go example, push it to
// a target VM, and execute it as one or more guest users. Snapshot lifecycle
// is controlled by NoRestore / NoStop so iterative debugging doesn't pay
// the revert cost on every run.
//
// AsUser semantics:
//   - "" or vm.User              → run as the existing admin via ssh.
//   - any other name             → provision the user, run via Task Scheduler.
//   - Matrix=true                → run admin then lowuser, label each block,
//                                  return the worst rc. AsUser is ignored.
type RunBinaryOpts struct {
	BinPath   string // path to a Go package dir or a pre-built executable
	AsUser    string // username on the guest; "" means vm.User (admin)
	Matrix    bool   // when true, run admin + lowuser back-to-back
	NoRestore bool   // skip snapshot revert before run (assume VM is up)
	NoStop    bool   // skip stop+restore after run (leave VM up for repeats)
}

// runUser tags a guest username with whether it is the configured admin
// account, so the dispatch loop doesn't have to re-derive it.
type runUser struct {
	name  string
	admin bool
}

// sshTarget bundles the SSH connection coordinates resolved once per VM.
// All scp/ssh helpers take this struct + a username so the admin path can
// reuse the same key/port for the lowuser path.
type sshTarget struct {
	vm   *VMConfig
	key  string
	port int
}

// RunBinaryOnVM cross-builds (if needed), provisions any unprivileged user,
// pushes the binary, and runs it. Output is mirrored to os.Stdout. Returns
// the worst guest exit code (0 on success). Only Windows guests are wired.
func RunBinaryOnVM(ctx context.Context, drv Driver, vm *VMConfig, opts RunBinaryOpts) int {
	if vm.Platform != "windows" {
		fmt.Fprintf(os.Stderr, "vmtest -bin: only windows guests are supported (got %s)\n", vm.Platform)
		return 2
	}
	exePath, err := ensureWindowsBinary(ctx, opts.BinPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n", err)
		return 1
	}
	exeName := filepath.Base(exePath)
	users := pickUsers(opts, vm.User)

	if !opts.NoRestore {
		if err := drv.Start(ctx, vm); err != nil {
			fmt.Fprintf(os.Stderr, "start: %v\n", err)
			return 1
		}
	}
	if !opts.NoStop {
		defer func() {
			if err := drv.Stop(ctx, vm); err != nil {
				fmt.Fprintf(os.Stderr, "stop: %v\n", err)
			}
			if err := drv.Restore(ctx, vm); err != nil {
				fmt.Fprintf(os.Stderr, "restore: %v\n", err)
			}
		}()
	}
	if err := drv.WaitReady(ctx, vm); err != nil {
		fmt.Fprintf(os.Stderr, "wait-ready: %v\n", err)
		return 1
	}

	key, err := resolveSSHKey(vm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ssh key: %v\n", err)
		return 1
	}
	tgt := sshTarget{vm: vm, key: key, port: sshPort(vm)}

	binGuest := guestWorkDir + `\` + exeName
	if err := scpUpload(ctx, tgt, vm.User, exePath, binGuest); err != nil {
		fmt.Fprintf(os.Stderr, "scp binary: %v\n", err)
		return 1
	}

	worstRC := 0
	for _, u := range users {
		fmt.Printf("\n========== %s @ %s — %s as %s ==========\n",
			drv.Name(), vm.SSHHost, exeName, u.name)
		var (
			rc     int
			output string
			runErr error
		)
		if u.admin {
			rc, output, runErr = runAsAdmin(ctx, tgt, u.name, binGuest)
		} else {
			if err := provisionLowuser(ctx, tgt, u.name, lowPassword); err != nil {
				fmt.Fprintf(os.Stderr, "provision %s: %v\n", u.name, err)
				worstRC = 1
				continue
			}
			rc, output, runErr = runAsScheduledTask(ctx, tgt, u.name, lowPassword, binGuest)
		}
		fmt.Print(output)
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "run as %s: %v\n", u.name, runErr)
			worstRC = 1
			continue
		}
		fmt.Printf("\n[exit rc=%d as %s]\n", rc, u.name)
		if rc != 0 && worstRC == 0 {
			worstRC = rc
		}
	}
	return worstRC
}

// pickUsers translates the flag combination into the user set to drive.
// Matrix wins over an explicit AsUser to keep the precedence obvious.
func pickUsers(opts RunBinaryOpts, adminUser string) []runUser {
	if opts.Matrix {
		return []runUser{{name: adminUser, admin: true}, {name: lowUser, admin: false}}
	}
	if opts.AsUser == "" || opts.AsUser == adminUser {
		return []runUser{{name: adminUser, admin: true}}
	}
	return []runUser{{name: opts.AsUser, admin: false}}
}

// runAsAdmin runs the already-pushed binary by ssh-ing as the configured
// admin user. cmd.exe /c with double-doubled quotes is the canonical way
// to invoke a path containing spaces under Windows OpenSSH.
func runAsAdmin(ctx context.Context, tgt sshTarget, user, binGuest string) (int, string, error) {
	out, err := sshCapture(ctx, tgt, user, fmt.Sprintf(`cmd.exe /c ""%s""`, binGuest))
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode(), string(out), nil
		}
		return 1, string(out), err
	}
	return 0, string(out), nil
}

// provisionLowuser pushes scripts/vm-test/provision-lowuser.ps1 to the guest
// and runs it as admin to (re)create the unprivileged account.
func provisionLowuser(ctx context.Context, tgt sshTarget, user, password string) error {
	scriptHost := filepath.Join("scripts", "vm-test", "provision-lowuser.ps1")
	scriptGuest := guestToolDir + `\provision-lowuser.ps1`
	if err := scpUpload(ctx, tgt, tgt.vm.User, scriptHost, scriptGuest); err != nil {
		return fmt.Errorf("scp provision script: %w", err)
	}
	provCmd := psCommand(fmt.Sprintf(
		"Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force; & '%s' -UserName '%s' -Password '%s'",
		scriptGuest, user, password))
	out, err := sshCapture(ctx, tgt, tgt.vm.User, provCmd)
	if err != nil {
		return fmt.Errorf("provision: %w (%s)", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(stripCLIXML(string(out))), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			fmt.Printf("[provision] %s\n", line)
		}
	}
	return nil
}

// runAsScheduledTask drives run-as-lowuser.ps1: pushes the script, runs it,
// parses the trailing "###RC=<n>" sentinel as the binary's exit code.
func runAsScheduledTask(ctx context.Context, tgt sshTarget, asUser, asPassword, binGuest string) (int, string, error) {
	scriptHost := filepath.Join("scripts", "vm-test", "run-as-lowuser.ps1")
	scriptGuest := guestToolDir + `\run-as-lowuser.ps1`
	if err := scpUpload(ctx, tgt, tgt.vm.User, scriptHost, scriptGuest); err != nil {
		return 1, "", fmt.Errorf("scp run-as-lowuser.ps1: %w", err)
	}
	cmd := fmt.Sprintf(
		`powershell -NoProfile -ExecutionPolicy Bypass -File %s -Binary "%s" -UserName %s -Password "%s"`,
		scriptGuest, binGuest, asUser, asPassword)
	out, err := sshCapture(ctx, tgt, tgt.vm.User, cmd)
	if err != nil {
		return 1, string(out), err
	}
	clean := stripCLIXML(string(out))
	rc := 0
	if m := reRC.FindStringSubmatch(clean); m != nil {
		if n, perr := strconv.Atoi(m[1]); perr == nil {
			rc = n
		}
	}
	body := reRC.ReplaceAllString(clean, "")
	return rc, body, nil
}

// ensureWindowsBinary returns a path to a Windows amd64 executable for binPath.
// If binPath is a directory, it is cross-built; if it is already an executable
// file (any extension) it is used as-is. Go's build cache makes repeat builds
// of an unchanged tree cheap, so no host-side caching is layered on top.
func ensureWindowsBinary(ctx context.Context, binPath string) (string, error) {
	info, err := os.Stat(binPath)
	if err != nil {
		return "", fmt.Errorf("stat %s: %w", binPath, err)
	}
	if !info.IsDir() {
		return binPath, nil
	}
	out := filepath.Join(os.TempDir(), filepath.Base(binPath)+".exe")
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./"+binPath)
	cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go build %s: %w", binPath, err)
	}
	return out, nil
}

// psCommand wraps a PowerShell snippet in `powershell -NoProfile
// -EncodedCommand <b64>`. UTF-16LE base64 (per PowerShell's contract via
// encode.PowerShell) bypasses every layer of shell quoting between the host
// and the guest interpreter.
func psCommand(script string) string {
	return "powershell -NoProfile -EncodedCommand " + encode.PowerShell(script)
}

// reRC matches the "###RC=<n>" sentinel emitted by run-as-lowuser.ps1.
// "###" prefix avoids collisions with anything the example might print.
var reRC = regexp.MustCompile(`(?m)^###RC=(-?\d+)\s*$`)

// stripCLIXML drops the CLIXML envelope PowerShell emits on stderr when a
// remote script writes to the error stream — keeps real stdout readable
// in the captured buffer.
func stripCLIXML(s string) string {
	out := reCLIXMLHeader.ReplaceAllString(s, "")
	return reCLIXMLBlock.ReplaceAllString(out, "")
}

var (
	reCLIXMLHeader = regexp.MustCompile(`(?m)^#< CLIXML\s*$`)
	reCLIXMLBlock  = regexp.MustCompile(`(?s)<Objs[^>]*>.*?</Objs>`)
)

// sshArgs builds the standard OpenSSH argument list for both `ssh` and `scp`.
// The port flag differs between the two binaries (`-p` vs `-P`), so callers
// pass it explicitly.
func sshArgs(tgt sshTarget, portFlag string) []string {
	return []string{
		"-i", tgt.key, portFlag, strconv.Itoa(tgt.port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
	}
}

// scpUpload copies a single host file to the guest using the named ssh user.
// PowerShell's Split-Path does the dirname split because filepath.Dir on a
// Linux host treats "\" as a regular character.
func scpUpload(ctx context.Context, tgt sshTarget, user, hostPath, guestPath string) error {
	if tgt.vm.SSHHost == "" {
		return errors.New("scpUpload: no ssh_host (WaitReady must run first)")
	}
	dirCmd := psCommand(fmt.Sprintf(
		"New-Item -ItemType Directory -Force -Path (Split-Path -Parent '%s') | Out-Null",
		guestPath))
	if err := sshRunUser(ctx, tgt, user, dirCmd); err != nil {
		return fmt.Errorf("mkdir guest: %w", err)
	}
	dst := fmt.Sprintf("%s@%s:%s", user, tgt.vm.SSHHost, guestPath)
	cmd := exec.CommandContext(ctx, "scp", append(sshArgs(tgt, "-P"), hostPath, dst)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// sshRunUser runs a remote command as the named user, streaming output.
func sshRunUser(ctx context.Context, tgt sshTarget, user, remoteCmd string) error {
	args := append(sshArgs(tgt, "-p"), fmt.Sprintf("%s@%s", user, tgt.vm.SSHHost), remoteCmd)
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// sshCapture runs a remote command as the named user and returns its
// combined stdout+stderr. On non-zero remote exit, the underlying
// *exec.ExitError is returned so the caller can read .ExitCode().
func sshCapture(ctx context.Context, tgt sshTarget, user, remoteCmd string) ([]byte, error) {
	args := append(sshArgs(tgt, "-p"), fmt.Sprintf("%s@%s", user, tgt.vm.SSHHost), remoteCmd)
	var buf bytes.Buffer
	cmd := exec.CommandContext(ctx, "ssh", args...)
	cmd.Stdout = io.MultiWriter(&buf)
	cmd.Stderr = io.MultiWriter(&buf)
	err := cmd.Run()
	return buf.Bytes(), err
}
