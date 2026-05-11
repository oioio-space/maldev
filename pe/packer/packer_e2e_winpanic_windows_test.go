//go:build windows && maldev_packer_run_e2e

package packer_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_WindowsPE_Panic_Vanilla_E2E baseline: vanilla
// pack of the panicking fixture must run + recover + print
// stdout. Establishes the regression line — if vanilla pack
// breaks panic+recover, the EXCEPTION walker test isn't
// trustworthy.
func TestPackBinary_WindowsPE_Panic_Vanilla_E2E(t *testing.T) {
	runPackedPanic(t, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
}

// TestPackBinary_WindowsPE_Panic_RandomizeAll_E2E exercises the
// EXCEPTION (.pdata) walker via the RandomizeImageVAShift opt
// that's part of RandomizeAll. Without the walker this fails
// because Go's Vectored Exception Handler invokes
// RtlVirtualUnwind which reads stale RVAs in the per-function
// UNWIND_INFO blocks.
func TestPackBinary_WindowsPE_Panic_RandomizeAll_E2E(t *testing.T) {
	runPackedPanic(t, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
		RandomizeAll: true,
	})
}

func runPackedPanic(t *testing.T, opts packer.PackBinaryOptions) {
	t.Helper()
	fixture := filepath.Join("testdata", "winpanic.exe")
	payload, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture missing (%v); run testdata/Makefile target winpanic", err)
	}
	packed, _, err := packer.PackBinary(payload, opts)
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	tmpDir := t.TempDir()
	packedPath := filepath.Join(tmpDir, "packed.exe")
	if err := os.WriteFile(packedPath, packed, 0o755); err != nil {
		t.Fatalf("write packed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, packedPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("subprocess exit %d", exitErr.ExitCode())
		} else {
			t.Fatalf("subprocess: %v (stderr: %q)", err, stderr.String())
		}
	}
	combined := stdout.String() + stderr.String()
	const want = "recovered=runtime error"
	if !strings.Contains(combined, want) {
		t.Fatalf("missing %q\nstdout: %q\nstderr: %q",
			want, stdout.String(), stderr.String())
	}
}
