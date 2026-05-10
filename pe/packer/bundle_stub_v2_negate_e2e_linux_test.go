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

// TestBundleStubV2Negate_E2E_NegateFlipsMatch is the runtime gate
// for §5 negate-flag support. Bundle layout exercising the negate
// path:
//
//   entry 0: PT_CPUID_VENDOR + Negate=true
//            VendorString = host's actual CPUID vendor
//            Binary = sys_exit(99)   ← would fire WITHOUT negate
//
//   entry 1: PT_MATCH_ALL fallback
//            Binary = sys_exit(42)   ← fires when entry 0 negates out
//
// Without negate handling, entry 0's vendor compare matches the
// host vendor, the entry "fires", and the binary exits 99.
//
// With negate (V2-Negate stub), entry 0's match outcome (1) gets
// XOR'd with negate=1 → 0 → entry 0 falls through, entry 1's
// PT_MATCH_ALL accepts → exit 42.
//
// Test asserts exit 42 → V2-Negate's entry-done logic is correct.
// Test FAIL with exit 99 → negate XOR didn't apply (entry 0 fired
// despite the flip).
func TestBundleStubV2Negate_E2E_NegateFlipsMatch(t *testing.T) {
	// Sniff the host's actual CPUID vendor for entry 0's VendorString.
	// Tests that run on a machine whose vendor we can't predict need
	// to match the actual CPUID output, not a hardcoded value.
	hostVendor := readHostCPUIDVendor()

	exit99Sc := []byte{
		// xor edi, edi; mov dil, 99; mov eax, 60; syscall
		0x31, 0xff, // xor edi, edi
		0x40, 0xb7, 0x63, // mov dil, 99
		0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
		0x0f, 0x05, // syscall
	}

	bundle, err := PackBinaryBundle(
		[]BundlePayload{
			{
				Binary: exit99Sc,
				Fingerprint: FingerprintPredicate{
					PredicateType: PTCPUIDVendor,
					VendorString:  hostVendor,
					Negate:        true, // flip the match outcome
				},
			},
			{
				Binary: testutil.LinuxExit42ShellcodeX64Compact,
				Fingerprint: FingerprintPredicate{
					PredicateType: PTMatchAll,
				},
			},
		},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	stub, immPos, err := bundleStubVendorAwareV2Negate()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2Negate: %v", err)
	}
	bundleOff := uint32(len(stub)) - 5
	binary.LittleEndian.PutUint32(stub[immPos:], bundleOff)

	combined := make([]byte, 0, len(stub)+len(bundle))
	combined = append(combined, stub...)
	combined = append(combined, bundle...)

	elfBytes, err := transform.BuildMinimalELF64(combined)
	if err != nil {
		t.Fatalf("BuildMinimalELF64: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "v2-negate")
	if err := os.WriteFile(exe, elfBytes, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (V2-Negate didn't dispatch)", exe, err)
	}
	got := exitErr.ExitCode()
	switch got {
	case 42:
		// entry 0 negated out, entry 1 fired. The desired path.
		t.Logf("V2-Negate bundle: %d B → exit=42 (negate flip OK)", len(elfBytes))
	case 99:
		t.Errorf("exit code = 99 — entry 0 (Negate=true vendor match) fired despite negate. Negate XOR didn't apply.")
	default:
		t.Errorf("exit code = %d, expected 42 (V2-Negate scan loop bug)", got)
	}
}

// TestBundleStubV2Negate_E2E_PTMatchAllStillWorks asserts the
// negate refactor doesn't break the simple PT_MATCH_ALL path
// (Negate=false, no vendor check). Single-entry bundle with
// just PT_MATCH_ALL → exit 42.
//
// SKIPPED 2026-05-10: V2-Negate produces SIGSEGV (exit 139) for
// the single-entry PT_MATCH_ALL case, while the 2-entry negate-
// flip case (TestBundleStubV2Negate_E2E_NegateFlipsMatch) PASSES
// with exit 42 — meaning the .matched-section + decrypt + JMP
// chain demonstrably works for at least one path through V2-N.
//
// Suspect: the discrepancy must be in the per-entry-test code that
// the PT_MATCH_ALL path traverses but the negate-flip path skips.
// Specifically the `jnz .entry_done` direct fast-path at offset
// 0x43. Both V2 (no-negate) and V2-Negate's negate-flip case run
// fine, only the V2-Negate's PT_MATCH_ALL fast-path crashes.
//
// Open suspects for the supervised pickup:
//   - golang-asm's encoding choice for the `xor rax, rax` at
//     .vendor_fail (offset 0x70 — 3 bytes `48 31 c0`) sits BEFORE
//     the .entry_done label. PT_MATCH_ALL jumps OVER it; verify
//     the JMP doesn't accidentally land mid-instruction.
//   - The MOVZX at .entry_done (`4d 0f b6 48 01`) decodes correctly
//     but verify the .next-via-fallthrough vs .matched-via-jnz
//     paths both end up at .next at offset 0x83, not somewhere in
//     between.
//   - Run via the asmtrace VEH harness on a Linux equivalent (port
//     the harness to use SIGSEGV signal handler) for a register
//     dump at the fault site.
func TestBundleStubV2Negate_E2E_PTMatchAllStillWorks(t *testing.T) {
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

	stub, immPos, err := bundleStubVendorAwareV2Negate()
	if err != nil {
		t.Fatalf("bundleStubVendorAwareV2Negate: %v", err)
	}
	bundleOff := uint32(len(stub)) - 5
	binary.LittleEndian.PutUint32(stub[immPos:], bundleOff)

	combined := append(append([]byte(nil), stub...), bundle...)
	elfBytes, err := transform.BuildMinimalELF64(combined)
	if err != nil {
		t.Fatalf("BuildMinimalELF64: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "v2-negate-ptmatchall")
	if err := os.WriteFile(exe, elfBytes, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("PT_MATCH_ALL via V2-Negate: exit=%d, want 42", got)
	}
}

// readHostCPUIDVendor returns the calling host's actual CPUID
// EAX=0 vendor as a [12]byte. Used by the negate test which needs
// to MATCH the host so Negate=true can flip it.
func readHostCPUIDVendor() [12]byte {
	// Use golang.org/x/sys/cpu's CPU.CacheLineSize-style facade.
	// Simpler: just call the CPUID intrinsic via inline asm — but
	// Go doesn't have inline asm in test files. Use the cpu package's
	// detected vendor instead.
	//
	// Fallback: golang.org/x/sys/cpu.X86.HasAVX etc. don't expose
	// the raw vendor; we derive it heuristically. For a real test
	// rig (Intel or AMD x86_64), the vendor is always one of the
	// canonical strings.
	//
	// Simplest correct solution: read /proc/cpuinfo on Linux.
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return [12]byte{}
	}
	const prefix = "vendor_id\t: "
	s := string(data)
	idx := indexOf(s, prefix)
	if idx < 0 {
		return [12]byte{}
	}
	idx += len(prefix)
	end := idx
	for end < len(s) && s[end] != '\n' {
		end++
	}
	if end-idx < 12 {
		return [12]byte{}
	}
	var v [12]byte
	copy(v[:], s[idx:idx+12])
	return v
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
