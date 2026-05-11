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

// TestPackBinary_WindowsPE_ImageBase_Alone_E2E isolates the
// RandomizeImageBase opt to find the actual failure mode
// (combined-opt crashes earlier could have masked it).
func TestPackBinary_WindowsPE_ImageBase_Alone_E2E(t *testing.T) {
	fixture := filepath.Join("testdata", "winhello.exe")
	payload, err := os.ReadFile(fixture)
	if err != nil {
		t.Skipf("fixture missing (%v)", err)
	}
	packed, _, err := packer.PackBinary(payload, packer.PackBinaryOptions{
		Format:             packer.FormatWindowsExe,
		Stage1Rounds:       3,
		Seed:               42,
		RandomizeImageBase: true,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	tmpDir := t.TempDir()
	packedPath := filepath.Join(tmpDir, "packed.exe")
	if err := os.WriteFile(packedPath, packed, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, packedPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("subprocess exit %d (0x%x)", exitErr.ExitCode(), uint32(exitErr.ExitCode()))
		} else {
			t.Logf("subprocess error: %v", err)
		}
	}
	t.Logf("stdout: %q", stdout.String())
	t.Logf("stderr: %q", stderr.String())
	if !strings.Contains(stdout.String()+stderr.String(), "hello from windows") {
		t.Fatalf("MISSING expected output — RandomizeImageBase broke something")
	}
}
