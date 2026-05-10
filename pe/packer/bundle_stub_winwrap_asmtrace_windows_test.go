//go:build windows && amd64

package packer_test

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/testutil"
)

// asmtraceCache builds the stage1 asmtrace VEH harness once per
// test process.
var (
	asmtraceCacheOnce sync.Once
	asmtraceCachePath string
	asmtraceCacheErr  error
)

func buildWinAsmtrace(t *testing.T) string {
	t.Helper()
	asmtraceCacheOnce.Do(func() {
		dir, err := os.MkdirTemp("", "asmtrace-cache-*")
		if err != nil {
			asmtraceCacheErr = err
			return
		}
		path := filepath.Join(dir, "asmtrace.exe")
		out, err := exec.Command("go", "build", "-o", path,
			"github.com/oioio-space/maldev/pe/packer/stubgen/stage1/asmtrace",
		).CombinedOutput()
		if err != nil {
			asmtraceCacheErr = err
			t.Logf("asmtrace build: %v\n%s", err, out)
			return
		}
		asmtraceCachePath = path
	})
	if asmtraceCacheErr != nil {
		t.Fatalf("buildWinAsmtrace: %v", asmtraceCacheErr)
	}
	return asmtraceCachePath
}

// TestWrapBundleAsExecutableWindows_StubAsmtrace_Diagnostic routes
// the v0.85.0 §4 PHASE A scan stub through the VEH-instrumented
// asmtrace harness instead of through the kernel-loaded PE path.
//
// Why this exists: the standard PE-wrapped E2E reports
// ACCESS_VIOLATION (0xc0000005) without any RIP / register info
// because the kernel terminates the wrapped process directly,
// out of reach of VEH inside our test process. asmtrace mmaps
// the asm in-process and registers VEH up front, so on crash we
// get the full register dump pinpointing the faulting instruction.
//
// Pipeline:
//
//   1. Get the scan-stub bytes via packer.BundleStubVendorAwareWindowsForTest()
//      (test export of the unexported helper).
//   2. Build a 1-payload PT_MATCH_ALL bundle with WindowsExit42ShellcodeX64.
//   3. Patch the bundleOff imm32 in the stub so PIC + add r15
//      lands on the bundle's first byte.
//   4. Concatenate stub + bundle.
//   5. Run via asmtrace.exe on the combined bytes.
//
// Expected outcomes:
//   - Stub correctly dispatches → matched payload's mov eax,42; ret
//     → asmtrace's syscall.SyscallN returns control → harness sees
//     "asm returned without calling ExitProcess" → exit 98.
//   - Stub crashes → asmtrace VEH catches it → register dump on
//     stderr → process dies with the OS exception code.
//   - Stub falls through to .§2 ExitProcess(0) → process exits 0
//     (the §2 primitive has its own validated exit path).
//
// Test reads the output and surfaces ANY register dump; fails on
// dump presence regardless of exit code (the dump means the stub
// has a runtime bug, even if it would have eventually exited).
func TestWrapBundleAsExecutableWindows_StubAsmtrace_Diagnostic(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("'go' not in PATH on the test VM")
	}

	// Build a 1-payload PT_MATCH_ALL bundle.
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

	// Get the stub bytes via the test-export.
	stub, err := packer.BundleStubVendorAwareWindowsForTest()
	if err != nil {
		t.Fatalf("BundleStubVendorAwareWindowsForTest: %v", err)
	}

	// Patch the bundleOff imm32 — same formula as the real wrap.
	bundleOff := uint32(len(stub)) - 5
	binary.LittleEndian.PutUint32(stub[packer.BundleOffsetImm32PosForTest:], bundleOff)

	// Concatenate stub + bundle.
	combined := make([]byte, 0, len(stub)+len(bundle))
	combined = append(combined, stub...)
	combined = append(combined, bundle...)

	// Write to a temp file.
	dir := t.TempDir()
	asmPath := filepath.Join(dir, "stub-with-bundle.bin")
	if err := os.WriteFile(asmPath, combined, 0o644); err != nil {
		t.Fatalf("write combined: %v", err)
	}

	// Run via asmtrace.
	harness := buildWinAsmtrace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, harness, asmPath)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("exec asmtrace: %v\n%s", err, out)
	}

	// Surface the asmtrace output regardless of exit code — the
	// register dump is the diagnostic signal we came here for.
	t.Logf("asmtrace exit=%#x stub-len=%d bundle-len=%d combined-len=%d\n--- asmtrace output ---\n%s\n--- end ---",
		uint32(exitCode), len(stub), len(bundle), len(combined),
		strings.TrimSpace(string(out)))

	if strings.Contains(string(out), "ASMTRACE: exception") {
		t.Errorf("scan stub crashed in asmtrace harness — see ASMTRACE: dump above for register state")
	}
}
