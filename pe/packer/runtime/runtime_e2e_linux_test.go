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

func TestRun_GoStaticPIE_E2E(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(),
		"MALDEV_PACKER_E2E_INNER=1",
		"MALDEV_PACKER_RUN_E2E=1",
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

	// Go's builtin print() writes to fd 2 (stderr), not stdout.
	// The loaded fixture uses print() so "hello from packer" appears
	// in stderr. Check both streams so the test stays green if a
	// future fixture switches to fmt.Println (fd 1).
	const want = "hello from packer"
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, want) {
		t.Errorf("combined output %q does not contain %q", combined, want)
	}
}
