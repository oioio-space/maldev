//go:build linux && maldev_packer_run_e2e

package packer_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinary_LinuxELF_E2E is the end-to-end smoke test for
// Phase 1e-B: pack a real Go static-PIE payload via
// packer.PackBinary(FormatLinuxELF), write the resulting ELF to a
// temp file, exec it as a subprocess with MALDEV_PACKER_RUN_E2E=1,
// and assert the original payload's "hello from packer" output
// appears in the subprocess's combined stdout+stderr.
//
// CURRENTLY FAILS — REGRESSION GUARD FOR THE PHASE 1e-A/B
// ARCHITECTURAL GAP. The unit tests in pe/packer/stubgen/* assert
// byte-shape correctness (debug/elf parses, PT_LOADs present, etc.)
// but never executed a generated binary. This E2E test does, and
// the subprocess crashes with no payload output. Two confirmed bugs:
//
//   1. amd64.Builder.LEA with MemOp{RIPRelative: true, Label: ...}
//      emits [abs 0x00000000] (SIB-based absolute addressing), NOT
//      [rip+disp32] — golang-asm's NAME_NONE + REG_NONE path
//      defaults to absolute. The decoder loop computes a NULL
//      pointer for the encoded payload's address → SIGSEGV on the
//      first MOVZBQ (%r8), %rax of the decode loop.
//
//   2. stage1.Round.Emit + stubgen.Generate never emit a final JMP
//      from end-of-stage-1 into the decoded stage-2 entry point.
//      Even with bug #1 fixed, after the last round's loop the
//      RIP would fall into uninitialised bytes after the asm.
//
// Both bugs are present in Phase 1e-A (Windows EXE) too — its E2E
// test was deferred behind Windows-VM scheduling so the gap was
// never caught. The architectural fix requires:
//
//   - Replace LEA-RIP-relative with CALL+POP+ADD (PIC shellcode
//     idiom) to learn the encoded payload's runtime address into
//     a callee-saved register
//   - Pass that register through all rounds without re-LEA per
//     round
//   - Emit a final JMP via that register to (encoded_addr +
//     stage2_entry_offset_within_encoded)
//   - Reconcile stage-2's file-vs-image layout so JMPing into the
//     decoded blob lands at runnable code (currently the blob is
//     a complete PE/ELF whose entry point doesn't trivially live
//     at a fixed file-offset). May require switching stage 2 to
//     position-independent shellcode (Donut/SRDI conversion of
//     stage2_main.go) instead of a Go EXE.
//
// See docs/refactor-2026-doc/KNOWN-ISSUES-1e.md for the full
// findings + fix plan. Until that lands, this test is the
// regression guard: when the architectural fix ships, this test
// passes and 1e-A/B graduate from "byte-shape correct" to
// "runtime correct".
//
// The chain exercised:
//   1. kernel exec the packed ELF → stage 1 entry
//   2. stage 1 SGN decoder loops peel encoded bytes in-place
//   3. stage 1 JMP into stage 2 (committed Linux Go static-PIE)
//   4. stage 2 _rt0_amd64_linux reads kernel-set SP frame
//   5. stage 2 main: os.Executable + bytes.Index sentinel + read trailer
//   6. stage 2 runtime.LoadPE(payload, key) — Phase 1f Stage E mapper
//   7. img.Run() — Phase 1f Stage C+D fake-stack frame + JMP
//   8. payload (hello_static_pie) print("hello from packer\n") + exit_group
//
// Build tag maldev_packer_run_e2e gates this test out of CI; opt
// in via:
//   go test -tags=maldev_packer_run_e2e ./pe/packer/...
func TestPackBinary_LinuxELF_E2E(t *testing.T) {
	// 1. Read the Phase 1f Stage E fixture as our payload.
	fixturePath := filepath.Join("..", "..", "pe", "packer", "runtime",
		"testdata", "hello_static_pie")
	fixturePath, err := filepath.Abs(fixturePath)
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}

	// 2. Pack into a Linux ELF static-PIE host.
	packedBytes, _, err := packer.PackBinary(payload, packer.PackBinaryOptions{
		Format:       packer.FormatLinuxELF,
		Stage1Rounds: 3,
		Seed:         1,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	if len(packedBytes) == 0 {
		t.Fatal("PackBinary returned empty host bytes")
	}

	// 3. Write to temp file and chmod +x.
	tmpDir := t.TempDir()
	packedPath := filepath.Join(tmpDir, "packed.elf")
	if err := os.WriteFile(packedPath, packedBytes, 0o755); err != nil {
		t.Fatalf("write packed: %v", err)
	}

	// 4. Exec with MALDEV_PACKER_RUN_E2E=1 set so stage 2's
	//    runtime.Run() un-gates and actually JMPs to the payload's
	//    entry point.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, packedPath)
	cmd.Env = append(os.Environ(), "MALDEV_PACKER_RUN_E2E=1")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	// The packed ELF may exit cleanly (status 0 from the payload's
	// exit_group(0)) or may segfault if any link in the chain is
	// broken. Either way, capture both streams and surface them in
	// the failure path.
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Logf("subprocess exit code %d (probably the payload's normal exit)", exitErr.ExitCode())
		} else {
			t.Fatalf("subprocess: %v (stderr: %q)", err, stderr.String())
		}
	}

	// 5. Assert the payload's stdout/stderr output appears.
	//    hello_static_pie uses Go's builtin print() which writes to
	//    fd 2 (stderr); checking both streams keeps the matcher
	//    robust if the fixture switches to fmt.Println later.
	const want = "hello from packer"
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, want) {
		t.Errorf("combined output does not contain %q\n\nstdout: %q\n\nstderr: %q",
			want, stdout.String(), stderr.String())
	}
}
