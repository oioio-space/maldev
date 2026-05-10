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
)

// exit42WinShellcode is 6 bytes of position-independent x86-64 that
// returns 42 to the caller:
//
//	b8 2a 00 00 00      mov eax, 42
//	c3                  ret
//
// On Windows, when a PE entry-point function returns, the kernel's
// thread-startup wrapper (ntdll!RtlUserThreadStart) calls
// ExitProcess(rax) on the main thread. Net effect: process exits
// with code 42 — reliable across Win10/11/Server 2019+ since the
// ABI hasn't changed.
//
// Important: the shellcode does NOT touch any Win32 API; it's pure
// position-independent code, exactly the shape PackShellcode is
// designed for. Operators shipping shellcode that ITSELF calls
// ExitProcess via PEB walk (the common msfvenom pattern) get the
// same wrapping treatment — this test just picks the simplest
// shellcode that gives a deterministic exit code.
var exit42WinShellcode = []byte{
	0xb8, 0x2a, 0x00, 0x00, 0x00, // mov eax, 42
	0xc3, // ret
}

// TestPackShellcode_E2E_PlainPEExits42Windows asserts the no-encrypt
// PE path produces a runnable .exe whose entry point reaches the
// shellcode's `mov eax, 42; ret` and the kernel exit-thunk yields
// code 42.
//
// VM-gated via scripts/vm-run-tests.sh windows.
func TestPackShellcode_E2E_PlainPEExits42Windows(t *testing.T) {
	out, _, err := packer.PackShellcode(exit42WinShellcode, packer.PackShellcodeOptions{
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
	out, _, err := packer.PackShellcode(exit42WinShellcode, packer.PackShellcodeOptions{
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
