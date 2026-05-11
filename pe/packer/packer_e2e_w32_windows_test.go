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

// TestPackBinary_WindowsPE_W32_Vanilla_E2E baseline: vanilla
// pack of the no-CRT mingw Win32 fixture must run + print
// stdout. Establishes that the packer handles non-Go MSVC-style
// payloads.
func TestPackBinary_WindowsPE_W32_Vanilla_E2E(t *testing.T) {
	runPackedW32(t, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
}

// TestPackBinary_WindowsPE_W32_RandomizeAll_E2E exercises every
// Phase 2 opt against a non-Go binary. Empirically this passes
// because the no-CRT binary's directory inventory (IMPORT +
// EXCEPTION + IAT only) is fully covered by the v0.104.0
// IMPORT walker.
func TestPackBinary_WindowsPE_W32_RandomizeAll_E2E(t *testing.T) {
	runPackedW32(t, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
		RandomizeAll: true,
	})
}

func runPackedW32(t *testing.T, opts packer.PackBinaryOptions) {
	t.Helper()
	fixture := filepath.Join("testdata", "winhello_w32.exe")
	payload, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture missing (%v); run testdata/Makefile target winhello_w32", err)
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
	const want = "hello from w32"
	if !strings.Contains(combined, want) {
		t.Fatalf("missing %q\nstdout: %q\nstderr: %q",
			want, stdout.String(), stderr.String())
	}
}
