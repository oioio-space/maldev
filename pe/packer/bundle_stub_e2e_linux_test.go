//go:build linux

package packer_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// exit42Shellcode mirrors the fixture used by transform's minimal-ELF
// test — same 12-byte exit(42) sequence so the all-asm path can prove
// itself with a payload that has no PE/ELF headers (the stub jumps
// into raw shellcode after decrypt).
var exit42Shellcode = []byte{
	0x31, 0xff,                   // xor edi, edi
	0x40, 0xb7, 0x2a,             // mov dil, 42
	0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
	0x0f, 0x05,                   // syscall
}

// TestWrapBundleAsExecutableLinux_RejectsBadInputs covers the two
// fast-path validation errors WrapBundleAsExecutableLinux surfaces
// before delegating to BuildMinimalELF64.
func TestWrapBundleAsExecutableLinux_RejectsBadInputs(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		_, err := packer.WrapBundleAsExecutableLinux([]byte{0x4D, 0x4C})
		if !errors.Is(err, packer.ErrBundleTruncated) {
			t.Errorf("err = %v, want ErrBundleTruncated", err)
		}
	})
	t.Run("badMagic", func(t *testing.T) {
		bogus := make([]byte, 64)
		_, err := packer.WrapBundleAsExecutableLinux(bogus)
		if !errors.Is(err, packer.ErrBundleBadMagic) {
			t.Errorf("err = %v, want ErrBundleBadMagic", err)
		}
	})
}

// TestWrapBundleAsExecutableLinux_RunsExit42 is the SHIP GATE for the
// all-asm bundle path. It exercises every layer:
//
//   - PackBinaryBundle wraps a 1-payload bundle around the exit42
//     shellcode (PTMatchAll predicate so every host fires payload 0).
//   - WrapBundleAsExecutableLinux emits the stub asm, patches its
//     RIP-relative bundle-offset immediate, concatenates stub + bundle,
//     and feeds the result to BuildMinimalELF64.
//   - The result lands as 0o755 on disk; the kernel maps the single
//     PT_LOAD RWX, jumps to the stub at vaddr+120.
//   - The stub resolves the bundle base via call/pop PIC, locates
//     PayloadEntry[0] from the wire-format header, XOR-decrypts the
//     data in place using the 16-byte rolling key, and JMPs to it.
//   - The decrypted bytes are exit42 shellcode → process exits 42.
//
// Asserts: exit code == 42, AND total binary size < 4 KiB (the
// elevation plan's stated goal — bundle binary that fits a "pretty
// poster"). Today's measurement: ~330 bytes (120 ELF header + 73 stub
// + 32 BundleHeader + 48 FingerprintEntry + 32 PayloadEntry + 12
// payload + 16 key … plus encryption overhead).
func TestWrapBundleAsExecutableLinux_RunsExit42(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42Shellcode,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinux: %v", err)
	}
	if len(wrapped) >= 4096 {
		t.Errorf("wrapped binary = %d bytes, want < 4096 (4 KiB target)", len(wrapped))
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "tiny-bundle")
	if err := os.WriteFile(exe, wrapped, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (not an ExitError; bundle didn't dispatch)", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %d, want 42", got)
	}

	t.Logf("all-asm bundle: %d bytes total → exit=42", len(wrapped))
}
