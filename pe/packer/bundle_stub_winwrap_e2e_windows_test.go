//go:build windows && amd64

package packer_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/testutil"
)

// TestWrapBundleAsExecutableWindows_E2E_RunsExit42Windows is the
// regression contract for §4 PHASE A: build a 1-payload PTMatchAll
// bundle, wrap into a Windows PE32+, run on Win10 VM, assert the
// matched payload's `mov eax,42; ret` is reached.
//
// The path exercises:
//
//   - bundleStubVendorAwareWindows() — the new Windows scan stub
//   - The 5-byte `jmp rel32` to §2 ExitProcess fallback (UNREACHED
//     on PT_MATCH_ALL match — but its presence requires the fall-
//     through Jcc displacements to still be correct)
//   - Decrypt loop + JMP into matched payload bytes
//   - The 6-byte exit42 shellcode reaching ntdll!RtlUserThreadStart's
//     ExitProcess(rax) on ret
//
// FAIL paths that VEH harness would diagnose (if we wired it here):
//   - Stub fails before reaching match → ACCESS_VIOLATION at stub RIP
//   - Decrypt produces wrong bytes → SIGILL at JMP target
//   - Match logic skips the entry → §2 fallback fires → exit 0 not 42
//
// VM-gated via scripts/vm-run-tests.sh windows.
//
// History: gated 2026-05-10 with t.Skip after the first dispatch
// returned 0xc0000005 — diagnosed via the asmtrace VEH harness
// (TestWrapBundleAsExecutableWindows_StubAsmtrace_Diagnostic) as a
// missing `add rsp, 16` to balance the CPUID prologue's stack
// allocation before the matched payload's `ret`. Fix landed in
// bundle_stub_winwrap.go's matched-tail patching. Skip removed.
func TestWrapBundleAsExecutableWindows_E2E_RunsExit42Windows(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: testutil.WindowsExit42ShellcodeX64,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	exe, err := packer.WrapBundleAsExecutableWindows(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableWindows: %v", err)
	}

	dir := t.TempDir()
	binPath := filepath.Join(dir, "wrapped.exe")
	if err := os.WriteFile(binPath, exe, 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath)
	err = cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec wrapped: %v (expected ExitError)", err)
	}
	got := exitErr.ExitCode()
	switch got {
	case 42:
		// PT_MATCH_ALL matched, decrypt+JMP delivered the shellcode,
		// shellcode set eax=42 and ret'd into RtlUserThreadStart.
	case 0:
		t.Errorf("exit code = 0 (§2 ExitProcess fallback fired — match logic must have skipped the PT_MATCH_ALL entry)")
	default:
		// Any other exit code (typically 0xc0000005) means the stub
		// crashed somewhere — likely a Jcc displacement off-by-one
		// or a stub-byte typo. Re-run via the asmtrace harness for
		// register state.
		t.Errorf("exit code = %#x, want 42 (stub crashed before reaching matched payload)", uint32(got))
	}
}
