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
)

// TestBundleStubV2NW_E2E_PTCpuidFeaturesWindows asserts the
// PT_CPUID_FEATURES predicate fires correctly on Windows via V2NW.
// Bundle: single entry with Mask=1 (SSE3 bit) + Value=1 (expect
// set). Every modern x86_64 CPU has SSE3 so the entry should match.
func TestBundleStubV2NW_E2E_PTCpuidFeaturesWindows(t *testing.T) {
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{
			Binary: testutil.WindowsExit42ShellcodeX64,
			Fingerprint: FingerprintPredicate{
				PredicateType:     PTCPUIDFeatures,
				CPUIDFeatureMask:  0x00000001,
				CPUIDFeatureValue: 0x00000001,
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
	binPath := filepath.Join(dir, "v2nw-features.exe")
	if err := os.WriteFile(binPath, exe, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, binPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec %q: %v (V2NW features path crashed)", binPath, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit = %#x, want 42 (PT_CPUID_FEATURES match)", uint32(got))
	} else {
		t.Logf("V2NW PT_CPUID_FEATURES: %d B → exit=42 (SSE3 bit matched)", len(exe))
	}
}
