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

// TestBundleStubV2N_E2E_PTCpuidFeaturesMatchExit42 exercises the
// PT_CPUID_FEATURES predicate (Tier 🔴 #1.3) added to V2-Negate in
// commit pending. Bundle layout:
//
//   entry 0: PT_CPUID_FEATURES with Mask=1 (SSE3 bit) + Value=1
//            (expect SSE3 set on host). Every modern x86_64 CPU
//            since 2004 has SSE3.
//            Binary = LinuxExit42ShellcodeX64Compact
//
// The scan stub's per-entry test should:
//   1. test r9b, 4 → ZF=0 (PT_CPUID_FEATURES bit set)
//   2. load r10d from host features at [rsi+12]
//   3. and r10d, [r8+24] = host & 1 = 1 (SSE3 bit set)
//   4. cmp r10d, [r8+28] = compare 1 vs 1 → ZF=1
//   5. je .skip_features → keep R12B=1
//   6. .entry_done → branch on R12B → jnz .matched
//   7. exit 42
//
// FAIL (exit 0 from sys_exit_group fallback) = predicate broken.
func TestBundleStubV2N_E2E_PTCpuidFeaturesMatchExit42(t *testing.T) {
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{
			Binary: testutil.LinuxExit42ShellcodeX64Compact,
			Fingerprint: FingerprintPredicate{
				PredicateType:     PTCPUIDFeatures,
				CPUIDFeatureMask:  0x00000001, // SSE3 bit
				CPUIDFeatureValue: 0x00000001, // expect set
			},
		}},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	stub, immPos, err := bundleStubVendorAwareV2Negate()
	if err != nil {
		t.Fatalf("V2-Negate: %v", err)
	}
	bundleOff := uint32(len(stub)) - 5
	binary.LittleEndian.PutUint32(stub[immPos:], bundleOff)

	combined := append(append([]byte(nil), stub...), bundle...)
	elfBytes, err := transform.BuildMinimalELF64(combined)
	if err != nil {
		t.Fatalf("BuildMinimalELF64: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "v2n-features")
	if err := os.WriteFile(exe, elfBytes, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (PT_CPUID_FEATURES path crashed)", exe, err)
	}
	got := exitErr.ExitCode()
	switch got {
	case 42:
		t.Logf("V2N PT_CPUID_FEATURES: %d B → exit=42 (SSE3 bit matched)", len(elfBytes))
	case 0:
		t.Errorf("exit=0 — PT_CPUID_FEATURES predicate skipped or failed despite SSE3 being set")
	default:
		t.Errorf("exit=%d, want 42", got)
	}
}

// TestBundleStubV2N_E2E_PTCpuidFeaturesMismatchExitClean exercises
// the negative path: PT_CPUID_FEATURES with a Value the host CANNOT
// have (Value=0 with Mask=1 means "SSE3 bit must be 0" — every
// modern host has SSE3=1 so this fails). Fallback entry with
// PT_MATCH_ALL fires instead → exit 99.
func TestBundleStubV2N_E2E_PTCpuidFeaturesMismatchExitClean(t *testing.T) {
	exit99Sc := []byte{
		0x31, 0xff, // xor edi, edi
		0x40, 0xb7, 0x63, // mov dil, 99
		0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
		0x0f, 0x05, // syscall
	}

	bundle, err := PackBinaryBundle(
		[]BundlePayload{
			{
				// SSE3 must be 0 — impossible on modern x86_64.
				Binary: testutil.LinuxExit42ShellcodeX64Compact,
				Fingerprint: FingerprintPredicate{
					PredicateType:     PTCPUIDFeatures,
					CPUIDFeatureMask:  0x00000001,
					CPUIDFeatureValue: 0x00000000,
				},
			},
			{
				Binary:      exit99Sc,
				Fingerprint: FingerprintPredicate{PredicateType: PTMatchAll},
			},
		},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	stub, immPos, err := bundleStubVendorAwareV2Negate()
	if err != nil {
		t.Fatalf("V2-Negate: %v", err)
	}
	bundleOff := uint32(len(stub)) - 5
	binary.LittleEndian.PutUint32(stub[immPos:], bundleOff)

	combined := append(append([]byte(nil), stub...), bundle...)
	elfBytes, err := transform.BuildMinimalELF64(combined)
	if err != nil {
		t.Fatalf("BuildMinimalELF64: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "v2n-features-mismatch")
	if err := os.WriteFile(exe, elfBytes, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (mismatch path crashed)", exe, err)
	}
	got := exitErr.ExitCode()
	switch got {
	case 99:
		t.Logf("V2N PT_CPUID_FEATURES mismatch fallback: entry 0 skipped, entry 1 fired → exit=99")
	case 42:
		t.Errorf("exit=42 — entry 0 fired despite mismatching feature value (predicate logic broken)")
	default:
		t.Errorf("exit=%d, expected 99 (fallback)", got)
	}
}
