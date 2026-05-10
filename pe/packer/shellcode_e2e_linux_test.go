//go:build linux && amd64

package packer_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// exit42ShellcodeForPackShellcode is 12 bytes of position-independent x86-64 issuing
// the Linux exit_group syscall with status 42:
//
//	48 c7 c0 e7 00 00 00      mov rax, 231 (SYS_exit_group)
//	48 c7 c7 2a 00 00 00      mov rdi, 42
//	0f 05                     syscall
//
// Total: 17 bytes. No imports, no relocations — runs anywhere RWX.
var exit42ShellcodeForPackShellcode = []byte{
	0x48, 0xc7, 0xc0, 0xe7, 0x00, 0x00, 0x00, // mov rax, 231
	0x48, 0xc7, 0xc7, 0x2a, 0x00, 0x00, 0x00, // mov rdi, 42
	0x0f, 0x05, // syscall
}

// TestPackShellcode_E2E_PlainELFExits42 runs the no-encrypt path
// end-to-end on the host: shellcode → minimal ELF wrap → exec →
// assert exit code 42. Catches any structural mistake in the ELF
// writer that lets debug/elf parse but the kernel reject.
func TestPackShellcode_E2E_PlainELFExits42(t *testing.T) {
	out, _, err := packer.PackShellcode(exit42ShellcodeForPackShellcode, packer.PackShellcodeOptions{
		Format: packer.FormatLinuxELF,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "exit42-plain")
	if err := os.WriteFile(binPath, out, 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath)
	err = cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec: %v (expected ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("plain wrap exit code = %d, want 42", got)
	}
}

// TestPackShellcode_E2E_EncryptedELFExits42 runs the FULL encrypt
// path end-to-end: shellcode → minimal ELF (with sections) → PackBinary
// (SGN-style stub envelope) → exec → assert exit code 42.
//
// This is the regression contract for shellcode-as-input to the
// UPX-style packer: if the stub fails to decrypt the .text section
// in place, or fails to JMP back to the original entry, the kernel
// SIGSEGVs immediately. A green run proves the full chain works
// for raw position-independent code, not just Go-built binaries.
func TestPackShellcode_E2E_EncryptedELFExits42(t *testing.T) {
	out, _, err := packer.PackShellcode(exit42ShellcodeForPackShellcode, packer.PackShellcodeOptions{
		Format:  packer.FormatLinuxELF,
		Encrypt: true,
	})
	if err != nil {
		t.Fatalf("PackShellcode (encrypted): %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "exit42-enc")
	if err := os.WriteFile(binPath, out, 0o755); err != nil {
		t.Fatalf("write binary: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath)
	err = cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("encrypted exec: %v (expected ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("encrypted wrap exit code = %d, want 42 (stub did not decrypt+jmp correctly)", got)
	}
}
