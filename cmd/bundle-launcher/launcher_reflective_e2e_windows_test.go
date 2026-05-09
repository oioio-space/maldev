//go:build windows

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestLauncher_E2E_ReflectiveLoadsExitCodeWindows is the Windows
// counterpart to TestLauncher_E2E_ReflectiveLoadsHello on Linux.
//
// Pipeline:
//
//	1. go-build a trivial 'exit 42' EXE on the test VM.
//	2. Pack it into a 1-payload PTMatchAll bundle.
//	3. go-build the launcher binary in a temp dir.
//	4. Append the bundle into the launcher via packer.AppendBundle.
//	5. Run the wrapped binary with MALDEV_REFLECTIVE=1 →
//	   the launcher's main() reads the bundle, matches PTMatchAll,
//	   calls executePayloadReflective which invokes
//	   pe/packer/runtime.Prepare + Run on the embedded payload.
//	6. Assert the wrapped binary exits with code 42.
//
// The reflective path differs from the default temp-file +
// CreateProcess flow:
//   - No transient TMP/* file for the payload — just an in-process
//     VirtualAlloc'd region.
//   - Process tree shows ONE binary (the launcher) — the payload
//     runs inside its address space; no child PID surfaces.
//
// Skips when 'go' isn't on PATH (Windows VM provisioning ought to
// install it, but defensive skip avoids a flaky red on misconfigured
// VMs). Also skips when go's embedded TestMain hijacks the path,
// which it doesn't here, but the pattern matches our other e2e
// tests.
func TestLauncher_E2E_ReflectiveLoadsExitCodeWindows(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("'go' not in PATH on the VM — install it via the test harness provisioning")
	}

	dir := t.TempDir()

	// 1. Build the exit42 payload.
	src := filepath.Join(dir, "exit42.go")
	if err := os.WriteFile(src, []byte(
		"package main\nimport \"os\"\nfunc main() { os.Exit(42) }\n",
	), 0o644); err != nil {
		t.Fatalf("write exit42.go: %v", err)
	}
	exit42Path := filepath.Join(dir, "exit42.exe")
	if out, err := exec.Command("go", "build", "-o", exit42Path, src).CombinedOutput(); err != nil {
		t.Fatalf("go build exit42: %v\noutput: %s", err, out)
	}
	exit42Bytes, err := os.ReadFile(exit42Path)
	if err != nil {
		t.Fatalf("read exit42.exe: %v", err)
	}

	// 2. Pack into a 1-payload PTMatchAll bundle (canonical magics —
	// no per-build secret needed for an E2E that builds and tests
	// matched pairs in one go).
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42Bytes,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	// 3. Build the launcher binary in the same temp dir.
	launcherPath := filepath.Join(dir, "bundle-launcher.exe")
	if out, err := exec.Command("go", "build", "-o", launcherPath,
		"github.com/oioio-space/maldev/cmd/bundle-launcher",
	).CombinedOutput(); err != nil {
		t.Fatalf("go build launcher: %v\noutput: %s", err, out)
	}
	launcherBytes, err := os.ReadFile(launcherPath)
	if err != nil {
		t.Fatalf("read launcher: %v", err)
	}

	// 4. Append the bundle.
	wrapped := packer.AppendBundle(launcherBytes, bundle)
	wrappedPath := filepath.Join(dir, "app.exe")
	if err := os.WriteFile(wrappedPath, wrapped, 0o755); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	// 5. Run with MALDEV_REFLECTIVE=1.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, wrappedPath)
	cmd.Env = append(os.Environ(), "MALDEV_REFLECTIVE=1")

	out, err := cmd.CombinedOutput()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("reflective run: %v (expected ExitError)\noutput: %s", err, out)
	}
	// 6. Assert exit code 42.
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("reflective exit code = %d, want 42 (output: %q)", got, out)
	}
}
