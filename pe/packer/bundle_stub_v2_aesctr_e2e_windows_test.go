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

// TestBundleStubV2NW_E2E_AESCTR is the regression contract for
// Tier 🟡 #2.2 Phase 3c-wire: pack a payload with CipherType=2
// (AES-128-CTR), wrap as Windows PE32+ via the V2NW stub, run on
// the win10 VM, assert exit code 42.
//
// Path under test:
//
//   1. PackBinaryBundle encrypts the shellcode with AES-CTR (random
//      key + IV), pads plaintext to 16-byte boundary, appends
//      crypto.ExpandAESKey output, auto-injects the AES-NI feature
//      bit into PT_CPUID_FEATURES.
//   2. WrapBundleAsExecutableWindows wraps in V2NW stub.
//   3. V2NW stub: PIC trampoline → CPUID prologue → PEB read → CPUID
//      features probe → scan loop → matched entry → CipherType
//      dispatch reads [RCX+12], sees 2, jumps to .aes_ctr_path.
//   4. emitAESCTRDecryptLoop: loads IV → XMM0, derives round-keys
//      pointer in R8, loops AES-CTR block decrypt + BE counter
//      increment until R9 reaches 0.
//   5. JMP RDI into the decrypted plaintext (exit42 shellcode).
//   6. mov eax, 42; ret → ntdll!RtlUserThreadStart calls
//      ExitProcess(42).
func TestBundleStubV2NW_E2E_AESCTR(t *testing.T) {
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{
			Binary: testutil.WindowsExit42ShellcodeX64,
			Fingerprint: FingerprintPredicate{
				PredicateType: PTMatchAll,
			},
			CipherType: CipherTypeAESCTR,
		}},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	exe, err := WrapBundleAsExecutableWindows(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableWindows: %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "v2nw-aesctr.exe")
	if err := os.WriteFile(binPath, exe, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, binPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec %q: %v (V2NW AES-CTR path crashed)", binPath, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %#x (%d), want 42 — V2NW AES-CTR decrypt produced wrong bytes",
			uint32(got), got)
	} else {
		t.Logf("V2NW AES-CTR: %d B → exit=42 (full AES-NI decrypt round-trip)", len(exe))
	}
	// Touch transform import so this file holds it cleanly if the
	// shape ever changes.
	_ = transform.MinimalPE32PlusImageBase
}
