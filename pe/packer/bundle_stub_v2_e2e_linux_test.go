//go:build linux && amd64

package packer

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/testutil"
)

// TestBundleStubV2_E2E_RunsExit42 is Phase 3 of the Builder
// migration — runtime functional-equivalence gate.
//
// Wires V2 (bundleStubVendorAwareV2) into the same wrap pipeline
// the existing TestWrapBundleAsExecutableLinux_RunsExit42 uses,
// but with V2 stub bytes instead of V1's hand-encoded bundle stub.
// If the V2-driven binary exits 42, V2 is functionally equivalent
// to V1 on real Linux runtime — regardless of byte-level encoding
// differences.
//
// Test flow:
//   1. Pack a 1-payload PT_MATCH_ALL bundle wrapping
//      LinuxExit42ShellcodeX64Compact (sys_exit(42)).
//   2. Get V2 stub bytes; patch imm32 with bundle offset
//      (= len(stub) - 5, matching V1's PIC convention).
//   3. Concatenate stub + bundle.
//   4. Wrap as a minimal ELF64 ET_EXEC via the canonical helper.
//   5. Exec the resulting binary; assert exit code 42.
//
// PASS = V2 dispatches correctly through PIC + CPUID + scan loop +
// matched section + decrypt + JMP + exit_group(42). The existing
// V1 tests stay green because V1 is untouched.
func TestBundleStubV2_E2E_RunsExit42(t *testing.T) {
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{
			Binary: testutil.LinuxExit42ShellcodeX64Compact,
			Fingerprint: FingerprintPredicate{
				PredicateType: PTMatchAll,
			},
		}},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	stub, immPos, err := bundleStubVendorAwareV2()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2: %v", err)
	}
	// Patch the bundle-offset imm32 — bundle data starts at the
	// byte immediately after the stub.
	bundleOff := uint32(len(stub)) - 5 // distance from .pic label
	binary.LittleEndian.PutUint32(stub[immPos:], bundleOff)

	combined := make([]byte, 0, len(stub)+len(bundle))
	combined = append(combined, stub...)
	combined = append(combined, bundle...)

	elfBytes, err := transform.BuildMinimalELF64(combined)
	if err != nil {
		t.Fatalf("BuildMinimalELF64: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "v2-bundle")
	if err := os.WriteFile(exe, elfBytes, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (not an ExitError; V2 bundle didn't dispatch)", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("V2 exit code = %d, want 42 (V2 stub broke the dispatch path)", got)
	}

	t.Logf("V2 all-asm bundle: %d bytes (stub=%d bundle=%d) → exit=42",
		len(elfBytes), len(stub), len(bundle))
}
