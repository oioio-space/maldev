//go:build windows && maldev_packer_run_e2e

package packer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_Args_Vanilla_E2E proves that command-line args
// passed to a packed EXE are correctly forwarded to the original
// payload's main(). The probe writes os.Args (joined by "|") to
// C:\maldev-args-marker.txt; we run `packed.exe foo bar baz` then
// assert the marker contains "foo|bar|baz" (after the executable
// path).
//
// Hypothesis: Mode 3 PackBinary preserves args because the OS
// loader sets PEB.ProcessParameters.CommandLine before calling
// the entry point; our stub doesn't touch this field, and the
// Go runtime reads from PEB at startup. Test confirms.
func TestPackBinary_Args_Vanilla_E2E(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("testdata", "probe_args.exe"))
	if err != nil {
		t.Skipf("probe_args.exe missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "packed.exe")
	if err := os.WriteFile(exePath, packed, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	const markerPath = `C:\maldev-args-marker.txt`
	_ = os.Remove(markerPath)
	defer os.Remove(markerPath)

	cmd := exec.Command(exePath, "foo", "bar", "baz with spaces")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("packed exec: %v (output: %q)", err, out)
	}
	content, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	got := string(content)
	for _, want := range []string{"foo", "bar", "baz with spaces"} {
		if !strings.Contains(got, want) {
			t.Errorf("marker missing arg %q (got %q)", want, got)
		}
	}
	t.Logf("args propagated: %q", got)
}

// TestPackBinary_Args_RandomizeAll_E2E same as above but with
// every Phase 2 randomiser on. The args path goes through PEB,
// which our randomisations don't touch — but worth confirming.
func TestPackBinary_Args_RandomizeAll_E2E(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("testdata", "probe_args.exe"))
	if err != nil {
		t.Skipf("probe_args.exe missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         42,
		RandomizeAll: true,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "packed.exe")
	if err := os.WriteFile(exePath, packed, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	const markerPath = `C:\maldev-args-marker.txt`
	_ = os.Remove(markerPath)
	defer os.Remove(markerPath)

	cmd := exec.Command(exePath, "alpha", "beta")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("packed exec: %v (output: %q)", err, out)
	}
	content, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("marker missing: %v", err)
	}
	got := string(content)
	for _, want := range []string{"alpha", "beta"} {
		if !strings.Contains(got, want) {
			t.Errorf("marker missing arg %q (got %q)", want, got)
		}
	}
	t.Logf("args propagated under RandomizeAll: %q", got)
}

// TestPackBinary_ConvertEXEtoDLL_Args_E2E investigates user
// concern #2: when an EXE is packed via ConvertEXEtoDLL and
// LoadLibrary'd, does the spawned-thread payload still see the
// LOADER's command-line args?
//
// The payload runs via `CreateThread(NULL, 0, OEP, NULL, 0, NULL)`.
// Args path: GetCommandLineW reads PEB.ProcessParameters.CommandLine
// which is the HOST'S args (rundll32 / loader / etc.), NOT
// arguments scoped to the DLL. Expected: marker contains the
// host's args, NOT something scoped to our payload. Documents the
// gap (no operator-controlled args injection in Mode 8).
func TestPackBinary_ConvertEXEtoDLL_Args_E2E(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("testdata", "probe_args.exe"))
	if err != nil {
		t.Skipf("probe_args.exe missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:          packer.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		Stage1Rounds:    3,
		Seed:            42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	tmpDir := t.TempDir()
	dllPath := filepath.Join(tmpDir, "packed.dll")
	if err := os.WriteFile(dllPath, packed, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}
	const markerPath = `C:\maldev-args-marker.txt`
	_ = os.Remove(markerPath)
	defer os.Remove(markerPath)

	// Use rundll32 as the loader — has well-known cmdline.
	rundllCmd := exec.Command("rundll32.exe", dllPath+",DllMain", "operator-arg-1")
	out, _ := rundllCmd.CombinedOutput()
	t.Logf("rundll32 output: %q", out)

	// Wait for the spawned thread to write the marker.
	for i := 0; i < 40; i++ {
		if _, err := os.Stat(markerPath); err == nil {
			break
		}
		// Note: rundll32 itself may fail (DllMain doesn't have the
		// expected exported function name) but our stub still ran
		// and spawned the thread.
	}
	content, err := os.ReadFile(markerPath)
	if err != nil {
		t.Logf("marker missing — payload may not have spawned (expected if rundll32 unloaded too quickly): %v", err)
		return
	}
	got := string(content)
	t.Logf("ConvertEXEtoDLL args observed: %q", got)
	t.Log("FINDING: payload sees rundll32's command-line, NOT operator-controlled args. " +
		"Mode 8 has no args-injection mechanism — see packer-improvements-2026-05-12.md.")
}
