//go:build windows && amd64

package stage1_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
)

// asmTraceCache caches the asmtrace harness build across the test
// suite — building it via `go build` per test would dominate
// runtime on a slow VM disk.
var (
	asmTraceOnce sync.Once
	asmTracePath string
	asmTraceErr  error
)

// buildAsmTrace compiles the Windows-only diagnostic harness once
// per test process. Returns the binary path.
func buildAsmTrace(t *testing.T) string {
	t.Helper()
	asmTraceOnce.Do(func() {
		dir, err := os.MkdirTemp("", "asmtrace-*")
		if err != nil {
			asmTraceErr = err
			return
		}
		path := filepath.Join(dir, "asmtrace.exe")
		out, err := exec.Command("go", "build", "-o", path,
			"github.com/oioio-space/maldev/pe/packer/stubgen/stage1/asmtrace",
		).CombinedOutput()
		if err != nil {
			asmTraceErr = err
			t.Logf("asmtrace build failed: %v\n%s", err, out)
			return
		}
		asmTracePath = path
	})
	if asmTraceErr != nil {
		t.Fatalf("buildAsmTrace: %v", asmTraceErr)
	}
	return asmTracePath
}

// TestEmitNtdllRtlExitUserProcess_RuntimeExits42Windows is the runtime
// regression contract for the §2 ExitProcess primitive, equipped with
// VEH-based diagnostics — when the asm faults, the test output
// contains a full register dump pinpointing the faulting instruction
// instead of an opaque ACCESS_VIOLATION.
//
// Pipeline:
//
//   1. Emit the asm for exit code 42.
//   2. Build the asmtrace harness (cached across tests).
//   3. Write the asm to a temp file; run `asmtrace asm.bin`.
//   4. Capture exit code + stderr.
//   5. Assert exit code 42 OR fail with the full ASMTRACE dump.
//
// VM-gated via scripts/vm-run-tests.sh windows.
func TestEmitNtdllRtlExitUserProcess_RuntimeExits42Windows(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("'go' not in PATH on the test VM")
	}

	b := mustBuilder(t)
	if err := stage1.EmitNtdllRtlExitUserProcess(b, 42); err != nil {
		t.Fatalf("EmitNtdllRtlExitUserProcess: %v", err)
	}
	asm := mustEncode(t, b)

	dir := t.TempDir()
	asmPath := filepath.Join(dir, "asm.bin")
	if err := os.WriteFile(asmPath, asm, 0o644); err != nil {
		t.Fatalf("write asm: %v", err)
	}

	harness := buildAsmTrace(t)

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

	if exitCode != 42 {
		// Surface the full ASMTRACE register dump.
		t.Errorf("exit code = %#x, want 42\n--- asmtrace output ---\n%s\n--- end ---",
			uint32(exitCode), strings.TrimSpace(string(out)))
	}
}
