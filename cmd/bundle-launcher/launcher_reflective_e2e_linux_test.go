//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestLauncher_E2E_ReflectiveLoadsHello packs the hello_static_pie
// fixture into a 1-payload bundle, wraps it into the launcher, then
// runs the wrapped binary with MALDEV_REFLECTIVE=1 so the in-process
// loader (pe/packer/runtime.Prepare + Run) handles the payload.
//
// The reflective path:
//
//   - mmap PT_LOADs into the launcher's address space (anonymous)
//   - apply R_X86_64_RELATIVE relocations
//   - mprotect each segment per its PF_* flags
//   - patch auxv to point at the loaded image (AT_PHDR/AT_ENTRY/...)
//   - jump to entry on a fake stack
//
// Distinguishes from TestLauncher_E2E_WrapAndRun:
//   - that test exits via memfd_create + execve (process tree =
//     launcher → execve → payload, two binaries in /proc).
//   - this test never forks; the loaded payload runs in the same
//     process image. /proc/self/maps shows anonymous segments where
//     execve would have shown a file path.
//
// We assert the payload's "hello from packer" output reached stderr
// (the fixture writes to stderr to keep stdout clean for the test
// harness).
func TestLauncher_E2E_ReflectiveLoadsHello(t *testing.T) {
	fixture := filepath.Join("..", "..", "pe", "packer", "runtime", "testdata", "hello_static_pie")
	abs, err := filepath.Abs(fixture)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	payload, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: payload,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	dir := t.TempDir()
	launcher := filepath.Join(dir, "bundle-launcher")
	if out, err := exec.Command("go", "build", "-o", launcher,
		"github.com/oioio-space/maldev/cmd/bundle-launcher").CombinedOutput(); err != nil {
		t.Fatalf("go build launcher: %v: %s", err, out)
	}
	launcherBytes, err := os.ReadFile(launcher)
	if err != nil {
		t.Fatalf("read launcher: %v", err)
	}
	wrapped := packer.AppendBundle(launcherBytes, bundle)
	wrappedPath := filepath.Join(dir, "app")
	if err := os.WriteFile(wrappedPath, wrapped, 0o755); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrappedPath)
	cmd.Env = append(os.Environ(), "MALDEV_REFLECTIVE=1")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("reflective run: %v\noutput: %q", err, out)
	}
	if !strings.Contains(string(out), "hello from packer") {
		t.Errorf("reflective payload did not surface 'hello from packer' marker\noutput: %q", out)
	}
}
