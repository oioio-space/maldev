//go:build windows && amd64

package packer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/testutil"
	"golang.org/x/sys/windows"
)

// TestBundleStubV2NW_E2E_PTMatchAllWindows asserts the V2NW Windows
// stub correctly dispatches a 1-entry PT_MATCH_ALL bundle into the
// matched payload. Same shape as the V1 Windows wrap E2E but using
// V2NW (which adds R13-saved OSBuildNumber + PT_WIN_BUILD predicate
// support).
func TestBundleStubV2NW_E2E_PTMatchAllWindows(t *testing.T) {
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{
			Binary: testutil.WindowsExit42ShellcodeX64,
			Fingerprint: FingerprintPredicate{
				PredicateType: PTMatchAll,
			},
		}},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	stub, immPos, err := bundleStubV2NegateWinBuildWindows()
	if err != nil {
		t.Fatalf("V2NW stub: %v", err)
	}
	patchBundleStubV2NWBundleOff(stub, immPos)

	combined := append(append([]byte(nil), stub...), bundle...)
	exe, err := transform.BuildMinimalPE32Plus(combined)
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "v2nw-ptmatchall.exe")
	if err := os.WriteFile(binPath, exe, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, binPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec %q: %v (V2NW didn't dispatch)", binPath, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %#x, want 42", uint32(got))
	} else {
		t.Logf("V2NW PT_MATCH_ALL: %d B → exit=42", len(exe))
	}
}

// TestBundleStubV2NW_E2E_PTWinBuildWindows asserts the PT_WIN_BUILD
// predicate fires correctly. Bundle:
//
//   entry 0: PT_WIN_BUILD with [BuildMin..BuildMax] covering the
//            host's actual OSBuildNumber → matches → exit 42
//
// If the host's build sits outside the range, entry 0 fails the
// build-range check (R12B → 0), no further entries, .no_match
// fires → §2 ExitProcess(0). We therefore expect exit 42 (range
// covers host) NOT exit 0.
//
// To make this robust, we use BuildMin=0, BuildMax=999999 — covers
// ANY Win10/11 build.
func TestBundleStubV2NW_E2E_PTWinBuildWindows(t *testing.T) {
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{
			Binary: testutil.WindowsExit42ShellcodeX64,
			Fingerprint: FingerprintPredicate{
				PredicateType: PTWinBuild,
				BuildMin:      0,
				BuildMax:      999999,
			},
		}},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	stub, immPos, err := bundleStubV2NegateWinBuildWindows()
	if err != nil {
		t.Fatalf("V2NW stub: %v", err)
	}
	patchBundleStubV2NWBundleOff(stub, immPos)

	combined := append(append([]byte(nil), stub...), bundle...)
	exe, err := transform.BuildMinimalPE32Plus(combined)
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "v2nw-ptwinbuild.exe")
	if err := os.WriteFile(binPath, exe, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, binPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		// On the host where BuildMin=0..BuildMax=999999, exit 42 is
		// expected. nil error means the process exited 0 cleanly,
		// which would mean PT_WIN_BUILD failed the range check —
		// shouldn't happen with our wide range.
		t.Fatalf("exec %q: %v (expected exit 42 from PT_WIN_BUILD match)", binPath, err)
	}
	got := exitErr.ExitCode()
	if got != 42 {
		// Read host build for diagnostic.
		v := windows.RtlGetVersion()
		t.Errorf("exit = %#x (host build %d, range [0..999999]); want 42",
			uint32(got), v.BuildNumber)
		return
	}
	t.Logf("V2NW PT_WIN_BUILD: %d B → exit=42 (host build matched range)", len(exe))
}
