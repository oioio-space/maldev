//go:build windows && amd64

package packer_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/testutil"
)

// TestPackShellcode_E2E_PlainPEExits42Windows asserts the no-encrypt
// PE path produces a runnable .exe whose entry point reaches the
// shellcode's `mov eax, 42; ret` and the kernel exit-thunk yields
// code 42.
//
// VM-gated via scripts/vm-run-tests.sh windows.
func TestPackShellcode_E2E_PlainPEExits42Windows(t *testing.T) {
	out, _, err := packer.PackShellcode(testutil.WindowsExit42ShellcodeX64, packer.PackShellcodeOptions{
		Format: packer.FormatWindowsExe,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "exit42-plain.exe")
	if err := os.WriteFile(binPath, out, 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath)
	err = cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("plain exec: %v (expected ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("plain Win wrap exit code = %d, want 42", got)
	}
}

// TestPackShellcode_E2E_EncryptedPEExits42Windows is the regression
// contract for raw-shellcode → encrypted PE on Windows. If the SGN
// stub fails to decrypt .text in place or fails to JMP back to the
// shellcode entry, Windows raises an access violation and we get
// 0xc0000005 instead of 42.
//
// VM-gated via scripts/vm-run-tests.sh windows.
func TestPackShellcode_E2E_EncryptedPEExits42Windows(t *testing.T) {
	out, _, err := packer.PackShellcode(testutil.WindowsExit42ShellcodeX64, packer.PackShellcodeOptions{
		Format:  packer.FormatWindowsExe,
		Encrypt: true,
	})
	if err != nil {
		t.Fatalf("PackShellcode (encrypted): %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "exit42-enc.exe")
	if err := os.WriteFile(binPath, out, 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath)
	err = cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("encrypted exec: %v (expected ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("encrypted Win wrap exit code = %#x, want 42 (stub didn't decrypt+jmp correctly)", got)
	}
}
