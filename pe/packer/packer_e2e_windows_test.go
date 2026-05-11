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

// TestPackBinary_WindowsPE_RandomizeAll_E2E proves the loader
// contract holds when every Phase 2 randomiser fires together —
// including 2-F-1 existing-section name randomisation. Packs the
// winhello.exe fixture with RandomizeAll=true, executes the
// resulting PE32+, and checks the payload's stdout appears.
//
// Build-tag gated (`maldev_packer_run_e2e`) so CI doesn't spawn
// arbitrary packed binaries by default. Run via:
//
//	go test -tags=maldev_packer_run_e2e ./pe/packer/...
func TestPackBinary_WindowsPE_RandomizeAll_E2E(t *testing.T) {
	fixture := filepath.Join("testdata", "winhello.exe")
	payload, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture missing (%v); build via testdata/Makefile", err)
	}

	packed, _, err := packer.PackBinary(payload, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
		RandomizeAll: true,
	})
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

	const want = "hello from windows"
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, want) {
		t.Fatalf("packed binary output missing %q\nstdout: %q\nstderr: %q",
			want, stdout.String(), stderr.String())
	}
}
