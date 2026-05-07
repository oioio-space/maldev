//go:build linux && maldev_packer_run_e2e

package runtime_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// runE2E spawns the test binary as its own subprocess in
// inner-harness mode, points it at `fixture` under testdata/,
// and asserts the loaded binary's combined stdout+stderr
// contains `want`. Shared between the Go and non-Go E2E tests.
func runE2E(t *testing.T, fixture, want string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"MALDEV_PACKER_E2E_INNER=1",
		"MALDEV_PACKER_RUN_E2E=1",
		"MALDEV_PACKER_E2E_FIXTURE="+fixture,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		// Subprocess exit 0 — clean run.
	} else if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 0 {
			t.Fatalf("subprocess exit code %d (stderr: %q)", exitErr.ExitCode(), stderr.String())
		}
	} else {
		t.Fatalf("subprocess: %v (stderr: %q)", err, stderr.String())
	}

	// Different fixtures land their output on different fds (Go
	// builtin print → stderr; raw write(2,...) → stdout). Check
	// both streams so the matcher stays robust to fixture choice.
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, want) {
		t.Errorf("combined output %q does not contain %q", combined, want)
	}
}

// TestRun_GoStaticPIE_E2E exercises the Stage C+D path: load the
// Go fixture, JMP to its _rt0_amd64_linux, observe the print()
// output that Go runtime sends to stderr.
func TestRun_GoStaticPIE_E2E(t *testing.T) {
	runE2E(t, "hello_static_pie", "hello from packer")
}

// TestRun_NonGoStaticPIE_E2E exercises Stage E's broadened gate:
// load the hand-rolled asm fixture, JMP to its _start, observe
// the raw-syscall write(2, ...) output. Confirms the loader
// handles non-Go static-PIE end-to-end without any Go-runtime
// assumptions in the load path.
func TestRun_NonGoStaticPIE_E2E(t *testing.T) {
	runE2E(t, "hello_static_pie_c", "hello from raw asm")
}
