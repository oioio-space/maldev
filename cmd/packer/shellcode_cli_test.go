//go:build linux && amd64

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// exit42SC is the 16-byte position-independent Linux exit_group(42)
// shellcode used by the CLI tests below.
var exit42SC = []byte{
	0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // mov rax, 231 (SYS_exit_group)
	0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, // mov rdi, 42
	0x0f, 0x05, // syscall
}

// buildPackerCLI compiles cmd/packer once per test process via the
// caller's TempDir. Returns the binary path. Mirrors the
// bundle-launcher sync.Once cache pattern.
func buildPackerCLI(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "packer-cli-*")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	bin := filepath.Join(dir, "packer")
	out, err := exec.Command("go", "build", "-o", bin,
		"github.com/oioio-space/maldev/cmd/packer").CombinedOutput()
	if err != nil {
		t.Fatalf("go build packer: %v\n%s", err, out)
	}
	return bin
}

// TestShellcodeCLI_PlainExits42 wires the CLI end-to-end:
// `packer shellcode -in sc -out p.elf -format linux-elf` → exec → 42.
func TestShellcodeCLI_PlainExits42(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("'go' not in PATH")
	}
	cli := buildPackerCLI(t)
	dir := t.TempDir()
	scPath := filepath.Join(dir, "sc.bin")
	if err := os.WriteFile(scPath, exit42SC, 0o644); err != nil {
		t.Fatalf("write sc: %v", err)
	}
	binPath := filepath.Join(dir, "out.elf")

	out, err := exec.Command(cli, "shellcode",
		"-in", scPath, "-out", binPath, "-format", "linux-elf",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("packer shellcode: %v\n%s", err, out)
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, binPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec: %v (want ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("plain CLI exit code = %d, want 42", got)
	}
}

// TestShellcodeCLI_EncryptedExits42 same flow with -encrypt.
// The CLI prints the AEAD key on stdout; the test ignores it (we
// just want to verify the wrapped binary runs).
func TestShellcodeCLI_EncryptedExits42(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("'go' not in PATH")
	}
	cli := buildPackerCLI(t)
	dir := t.TempDir()
	scPath := filepath.Join(dir, "sc.bin")
	if err := os.WriteFile(scPath, exit42SC, 0o644); err != nil {
		t.Fatalf("write sc: %v", err)
	}
	binPath := filepath.Join(dir, "out-enc.elf")
	keyPath := filepath.Join(dir, "key.hex")

	out, err := exec.Command(cli, "shellcode",
		"-in", scPath, "-out", binPath, "-format", "linux-elf",
		"-encrypt", "-keyout", keyPath,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("packer shellcode -encrypt: %v\n%s", err, out)
	}
	if err := os.Chmod(binPath, 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil || len(keyBytes) < 64 {
		t.Errorf("-keyout file not written (got %d bytes): %v", len(keyBytes), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, binPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec encrypted: %v (want ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("encrypted CLI exit code = %d, want 42", got)
	}
}

// TestShellcodeCLI_RejectsMissingFlags pins the CLI's required-flag
// validation: -in and -out are mandatory.
func TestShellcodeCLI_RejectsMissingFlags(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("'go' not in PATH")
	}
	cli := buildPackerCLI(t)
	out, err := exec.Command(cli, "shellcode").CombinedOutput()
	if err == nil {
		t.Errorf("packer shellcode (no args) succeeded: %s", out)
	}
}
