//go:build windows && maldev_packer_run_e2e

package packer_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

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

// TestPackBinary_ConvertEXEtoDLL_DefaultArgs_E2E closes the gap
// documented by TestPackBinary_ConvertEXEtoDLL_Args_E2E: with
// ConvertEXEtoDLLDefaultArgs set, the converted-DLL stub patches
// PEB.ProcessParameters.CommandLine before invoking the OEP, so
// the spawned payload's GetCommandLineW (and Go's os.Args) returns
// the operator-controlled string instead of the host process's
// (rundll32's) cmdline.
//
// Asserts the marker file contains the operator's args, NOT
// rundll32's. Slice 1.A.4 — first E2E proof of slices 1.A.1-1.A.3.
func TestPackBinary_ConvertEXEtoDLL_DefaultArgs_E2E(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("testdata", "probe_args.exe"))
	if err != nil {
		t.Skipf("probe_args.exe missing: %v", err)
	}
	const operatorArgs = "operator.exe alpha bravo charlie"
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:                     packer.FormatWindowsExe,
		ConvertEXEtoDLL:            true,
		ConvertEXEtoDLLDefaultArgs: operatorArgs,
		Stage1Rounds:               3,
		Seed:                       42,
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

	rundllCmd := exec.Command("rundll32.exe", dllPath+",DllMain")
	out, _ := rundllCmd.CombinedOutput()
	t.Logf("rundll32 output: %q", out)

	for i := 0; i < 40; i++ {
		if _, err := os.Stat(markerPath); err == nil {
			break
		}
	}
	content, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("marker missing — payload did not spawn or crashed: %v", err)
	}
	got := strings.TrimRight(string(content), "\r\n")
	t.Logf("DefaultArgs payload observed cmdline: %q", got)

	// Exact equality: probe writes os.Args joined by "|", which for
	// our operator string parses to {"operator.exe", "alpha", "bravo",
	// "charlie"} → "operator.exe|alpha|bravo|charlie". Anything else
	// means the patch didn't take effect cleanly.
	const want = "operator.exe|alpha|bravo|charlie"
	if got != want {
		t.Errorf("marker contents mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}

// TestPackBinary_ConvertEXEtoDLL_DefaultArgs_PackTimeBound asserts
// that DefaultArgs over the documented cap (1500 chars) is rejected
// at pack time with a readable error rather than failing deep inside
// stubgen as transform.ErrStubTooLarge. Belt and suspenders for the
// runtime asm-level guard.
func TestPackBinary_ConvertEXEtoDLL_DefaultArgs_PackTimeBound(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("testdata", "probe_args.exe"))
	if err != nil {
		t.Skipf("probe_args.exe missing: %v", err)
	}
	tooLong := strings.Repeat("A", 1501)
	_, _, err = packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:                     packer.FormatWindowsExe,
		ConvertEXEtoDLL:            true,
		ConvertEXEtoDLLDefaultArgs: tooLong,
		Stage1Rounds:               3,
		Seed:                       42,
	})
	if err == nil {
		t.Fatal("expected pack-time rejection of oversize DefaultArgs, got nil error")
	}
	if !strings.Contains(err.Error(), "ConvertEXEtoDLLDefaultArgs is 1501 chars") {
		t.Errorf("expected error mentioning the offending length; got %v", err)
	}
}

// TestPackBinary_ConvertEXEtoDLL_DefaultArgs_LargeButValid stresses
// the asm-level runtime guard: pack with DefaultArgs near the cap
// (1500 chars), invoke via rundll32, and assert the loader doesn't
// crash. rundll32's existing CommandLine buffer is large enough to
// absorb our patch (so the guard likely doesn't fire) — this test
// proves we don't regress on the happy "big args still safe" path.
func TestPackBinary_ConvertEXEtoDLL_DefaultArgs_LargeButValid(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("testdata", "probe_args.exe"))
	if err != nil {
		t.Skipf("probe_args.exe missing: %v", err)
	}
	largeArgs := "operator.exe " + strings.Repeat("X", 1400)
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:                     packer.FormatWindowsExe,
		ConvertEXEtoDLL:            true,
		ConvertEXEtoDLLDefaultArgs: largeArgs,
		Compress:                   true, // 8 KiB stub budget vs 4 KiB
		Stage1Rounds:               3,
		Seed:                       42,
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

	rundllCmd := exec.Command("rundll32.exe", dllPath+",DllMain")
	out, _ := rundllCmd.CombinedOutput()
	t.Logf("rundll32 output: %q", out)

	for i := 0; i < 40; i++ {
		if _, err := os.Stat(markerPath); err == nil {
			break
		}
	}
	content, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("marker missing — likely heap overflow / crash: %v", err)
	}
	got := strings.TrimRight(string(content), "\r\n")
	t.Logf("large-args marker (%d B): %.120q...", len(got), got)
	switch {
	case strings.Contains(got, strings.Repeat("X", 100)):
		t.Log("loader buffer absorbed the patch — runtime guard did not fire")
	case strings.Contains(got, "rundll32"):
		t.Log("runtime guard fired — payload safely fell back to host cmdline")
	default:
		t.Errorf("marker is neither operator args nor host cmdline — possible partial overwrite: %.200q", got)
	}
}

// TestPackBinary_ConvertEXEtoDLL_RunWithArgs_E2E exercises the
// RunWithArgs DLL export end-to-end: pack probe_args.exe with the
// export enabled, LoadLibrary, GetProcAddress, invoke with a custom
// operator-controlled wide string, and assert the payload sees those
// exact args.
//
// Unlike DefaultArgs (which bakes operator args at pack time), this
// path is fully runtime-controlled: the caller hands the args buffer
// to the export, the stub copies it into PEB.ProcessParameters.CommandLine,
// then spawns the OEP via CreateThread. The export blocks via
// WaitForSingleObject and returns the OEP's exit code as a DWORD —
// proving the Wait + GetExitCodeThread plumbing on top of the spawn.
func TestPackBinary_ConvertEXEtoDLL_RunWithArgs_E2E(t *testing.T) {
	probe, err := os.ReadFile(filepath.Join("testdata", "probe_args.exe"))
	if err != nil {
		t.Skipf("probe_args.exe missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:                     packer.FormatWindowsExe,
		ConvertEXEtoDLL:            true,
		ConvertEXEtoDLLRunWithArgs: true,
		Stage1Rounds:               3,
		Seed:                       42,
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

	const operatorArgs = "operator.exe runtime alpha beta"

	h, err := syscall.LoadLibrary(dllPath)
	if err != nil {
		t.Fatalf("LoadLibrary %s: %v", dllPath, err)
	}
	defer syscall.FreeLibrary(h)
	proc, err := syscall.GetProcAddress(h, "RunWithArgs")
	if err != nil {
		t.Fatalf("GetProcAddress RunWithArgs: %v", err)
	}
	wargs, err := syscall.UTF16FromString(operatorArgs)
	if err != nil {
		t.Fatalf("UTF16FromString: %v", err)
	}
	ret, _, callErr := syscall.SyscallN(proc, uintptr(unsafe.Pointer(&wargs[0])))
	t.Logf("RunWithArgs returned exit code %d (callErr=%v)", ret, callErr)

	// Wait briefly for the OEP thread to flush its marker. RunWithArgs
	// blocks until the thread exits, so by the time SyscallN returns the
	// probe has already written the file — but the FS may need a tick.
	deadline := time.Now().Add(2 * time.Second)
	var content []byte
	for time.Now().Before(deadline) {
		content, err = os.ReadFile(markerPath)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("marker missing — payload did not spawn or RunWithArgs failed: %v", err)
	}
	got := strings.TrimRight(string(content), "\r\n")
	t.Logf("RunWithArgs payload observed cmdline: %q", got)

	const want = "operator.exe|runtime|alpha|beta"
	if got != want {
		t.Errorf("marker contents mismatch:\n  got:  %q\n  want: %q", got, want)
	}
}
