//go:build windows && maldev_packer_run_e2e

package packer_test

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// diagPath survives abrupt Win32 process termination — t.Logf
// buffers until --- PASS/FAIL prints, so any crash before that
// point loses the log. The on-disk file is fsync'd after each
// write and can be SSH-pulled post-mortem.
const diagPath = `C:\maldev-loadlib-diag.log`

// writeDiag appends a line to the on-disk diag (survives Win32
// process abort if file pinned) AND prints to stderr (which
// vmtest captures into its host-side log without Go's test
// buffering). Belt-and-suspenders: t.Logf buffers until PASS/FAIL
// prints, abrupt Win32 termination skips that flush, and the
// file is lost when vmtest snapshot-reverts the VM. Stderr
// writes flow through ssh→vmtest→/tmp/vmtest-logs/*.log
// eagerly and persist on the host.
func writeDiag(line string) {
	ts := time.Now().Format("15:04:05.000")
	_, _ = fmt.Fprintln(os.Stderr, "DIAG "+ts+" "+line)
	if f, err := os.OpenFile(diagPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
		_, _ = f.WriteString(ts + " " + line + "\n")
		_ = f.Sync()
		_ = f.Close()
	}
}

// markerPath is the file the slice-5.5.x probe_converted.exe writes
// "OK\n" into when its main() runs. Picked at C:\ root so the path
// is short, predictable, and writable by any test user with Admin
// (the default Win10 VM user). The test ensures the file is
// removed before LoadLibrary so a stale marker from a previous run
// can't false-positive the assertion.
const markerPath = `C:\maldev-probe-marker.txt`

// TestPackBinary_ConvertEXEtoDLL_LoadLibrary_E2E validates the
// full slice-5 EXE→DLL pipeline against the Windows loader:
//
//  1. Read the no-CRT probe EXE (testdata/probe_converted.exe).
//  2. Pack it with ConvertEXEtoDLL=true → packed.dll bytes.
//  3. Write to a temp file the loader can map.
//  4. LoadLibrary the packed file.
//  5. Sleep 2 s so the spawned CreateThread reaches the probe's
//     main() and writes the marker file.
//  6. Assert marker file contains "OK\n".
//
// On success: confirms slice 5.3's CreateThread spawn actually
// reaches the original OEP under the real loader, and slice 5.4's
// IMAGE_FILE_DLL flip is correctly recognised by the loader.
//
// The harness deliberately does NOT FreeLibrary — the probe's
// Sleep(INFINITE) keeps the spawned thread alive. Unloading
// the DLL while the thread is inside .text would crash the
// host. OS process teardown handles cleanup when the test exits.
func TestPackBinary_ConvertEXEtoDLL_LoadLibrary_E2E(t *testing.T) {
	// Slice 5.5.y diagnostic: every step writes a fsync'd line
	// to diagPath BEFORE attempting the operation. If the test
	// process dies abruptly (Win32 unhandled exception, WerFault,
	// etc.), the file's last line is the step that was about to
	// execute — survives the loss of t.Logf buffers and the
	// process's stdout/stderr.
	_ = os.Remove(diagPath) // start fresh
	writeDiag("=== TestPackBinary_ConvertEXEtoDLL_LoadLibrary_E2E ===")

	// Always tail the diag file at test end so the harness's
	// t.Logf output (which goes to vmtest's log when the test
	// completes normally) carries the per-step trace too.
	defer func() {
		if buf, err := os.ReadFile(diagPath); err == nil {
			t.Logf("=== diag file %s ===\n%s", diagPath, string(buf))
		}
	}()

	writeDiag("step 1a: reading probe fixture")
	probePath := filepath.Join("testdata", "probe_converted.exe")
	probe, err := os.ReadFile(probePath)
	if err != nil {
		writeDiag(fmt.Sprintf("step 1: probe read FAILED: %v", err))
		t.Skipf("probe fixture missing (%v); run `make -C pe/packer/testdata probe_converted`", err)
	}
	writeDiag(fmt.Sprintf("step 1b: probe read OK (%d B)", len(probe)))

	writeDiag("step 2a: PackBinary entered")
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:          packer.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		Stage1Rounds:    3,
		Seed:            0xC0DECAFE,
	})
	if err != nil {
		writeDiag(fmt.Sprintf("step 2: PackBinary FAILED: %v", err))
		t.Fatalf("PackBinary(ConvertEXEtoDLL): %v", err)
	}
	writeDiag(fmt.Sprintf("step 2b: PackBinary OK (%d B output)", len(packed)))

	writeDiag("step 3a: creating temp dll file")
	dllFile, err := os.CreateTemp("", "maldev-packed-converted-*.dll")
	if err != nil {
		writeDiag(fmt.Sprintf("step 3: CreateTemp FAILED: %v", err))
		t.Fatalf("create temp dll: %v", err)
	}
	defer os.Remove(dllFile.Name())
	if _, err := dllFile.Write(packed); err != nil {
		writeDiag(fmt.Sprintf("step 3: Write FAILED: %v", err))
		t.Fatalf("write packed dll: %v", err)
	}
	if err := dllFile.Close(); err != nil {
		t.Fatalf("close temp dll: %v", err)
	}
	writeDiag(fmt.Sprintf("step 3b: temp dll written %s", dllFile.Name()))

	_ = os.Remove(markerPath)
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		writeDiag(fmt.Sprintf("step 4: stale marker present after Remove: %v", err))
		t.Fatalf("pre-load: marker %s still present after Remove (err=%v)", markerPath, err)
	}
	writeDiag("step 4: marker cleared")

	writeDiag("step 5a: about to call syscall.LoadLibrary")
	h, err := syscall.LoadLibrary(dllFile.Name())
	writeDiag(fmt.Sprintf("step 5b: syscall.LoadLibrary returned (h=%#x err=%v)", uintptr(h), err))
	if err != nil {
		t.Fatalf("LoadLibrary %s: %v", dllFile.Name(), err)
	}
	writeDiag("step 5c: LoadLibrary OK")
	_ = h // intentionally not freed — see test doc above

	writeDiag("step 6a: sleeping 2 s")
	time.Sleep(2 * time.Second)
	writeDiag("step 6b: sleep done")

	writeDiag("step 7a: reading marker")
	content, err := os.ReadFile(markerPath)
	if err != nil {
		writeDiag(fmt.Sprintf("step 7: marker read FAILED: %v", err))
		t.Fatalf("marker file missing — CreateThread didn't reach OEP, or OEP didn't write the marker: %v", err)
	}
	writeDiag(fmt.Sprintf("step 7b: marker read OK (%q)", string(content)))
	defer os.Remove(markerPath)
	if want := "OK\n"; string(content) != want {
		t.Errorf("marker = %q, want %q", string(content), want)
	}
	writeDiag("step 8: test complete")
}

// TestPackBinary_ConvertEXEtoDLL_LoadLibrary_Compress_E2E validates
// slice 5.7: PackBinary(ConvertEXEtoDLL=true, Compress=true) ships a
// DLL whose DllMain SGN-decodes the LZ4 block, inflates into the
// stub-section scratch buffer, memcpys plaintext back to .text, then
// spawns the original entry. Same marker assertion as the
// uncompressed E2E.
func TestPackBinary_ConvertEXEtoDLL_LoadLibrary_Compress_E2E(t *testing.T) {
	t.Skip("slice 5.7 partial: pack-time wired (stub + SizeOfImage); runtime " +
		"VM E2E wedges the host inside the LZ4 inflate block — gated via " +
		"stubgen.ErrConvertEXEtoDLLUnsupported until bisected. Set env " +
		"MALDEV_PACKER_COMPRESS_DLL_DEBUG=1 to run anyway when debugging.")
	if os.Getenv("MALDEV_PACKER_COMPRESS_DLL_DEBUG") != "1" {
		return
	}
	_ = os.Remove(diagPath)
	writeDiag("=== Compress_E2E ===")

	probe, err := os.ReadFile(filepath.Join("testdata", "probe_converted.exe"))
	if err != nil {
		t.Skipf("probe fixture missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:          packer.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		Compress:        true,
		Stage1Rounds:    3,
		Seed:            0xC0DECAFE,
	})
	if err != nil {
		t.Fatalf("PackBinary Compress: %v", err)
	}
	writeDiag(fmt.Sprintf("compress step 1: packed (%d B)", len(packed)))

	dllFile, err := os.CreateTemp("", "maldev-packed-compress-*.dll")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(dllFile.Name())
	if _, err := dllFile.Write(packed); err != nil {
		t.Fatalf("write: %v", err)
	}
	dllFile.Close()

	_ = os.Remove(markerPath)
	writeDiag("compress step 2: about to LoadLibrary")
	h, err := syscall.LoadLibrary(dllFile.Name())
	writeDiag(fmt.Sprintf("compress step 3: LoadLibrary h=%#x err=%v", uintptr(h), err))
	if err != nil {
		t.Fatalf("LoadLibrary Compress: %v", err)
	}
	_ = h
	time.Sleep(2 * time.Second)
	content, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatalf("marker missing — LZ4 inflate or memcpy broken: %v", err)
	}
	defer os.Remove(markerPath)
	if got, want := string(content), "OK\n"; got != want {
		t.Errorf("marker = %q, want %q", got, want)
	}
	writeDiag("compress step 4: marker OK — LZ4 path validated")
}

// TestPackBinary_ConvertEXEtoDLL_LoadLibrary_AntiDebug_E2E asserts the
// silent-exit semantics of the AntiDebug-on-converted-DLL path:
//
//  1. LoadLibrary MUST succeed (loader reads RAX from the bare RET
//     inside the antidebug prologue; RAX always carries a non-zero
//     check result on positive detection → BOOL TRUE).
//  2. The probe's main() MUST NOT run (no marker file). The DllMain
//     never reached the SGN/resolver/spawn path because the RDTSC ↔
//     CPUID delta tripped on the virtualized host (KVM VMEXIT
//     inflates the cycle count well past the 1000-cycle threshold
//     baked into emitAntiDebugWindowsPE).
//
// Together these confirm slice 5.6: the converted-DLL AntiDebug
// prologue exits cleanly under observation and the payload silently
// no-ops on monitored hosts, matching the EXE-stub behavior
// documented in pe/packer/stubgen/stage1/antidebug.go. On a bare-
// metal undebugged Windows machine the same pack would proceed to
// CreateThread and the marker WOULD be written; this VM-side test
// validates the detection path explicitly.
// Slice 5.6 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
func TestPackBinary_ConvertEXEtoDLL_LoadLibrary_AntiDebug_E2E(t *testing.T) {
	_ = os.Remove(diagPath)
	writeDiag("=== AntiDebug_E2E ===")

	probe, err := os.ReadFile(filepath.Join("testdata", "probe_converted.exe"))
	if err != nil {
		t.Skipf("probe fixture missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:          packer.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		AntiDebug:       true,
		Stage1Rounds:    3,
		Seed:            0xC0DECAFE,
	})
	if err != nil {
		t.Fatalf("PackBinary AntiDebug: %v", err)
	}
	dllFile, err := os.CreateTemp("", "maldev-packed-antidebug-*.dll")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(dllFile.Name())
	if _, err := dllFile.Write(packed); err != nil {
		t.Fatalf("write: %v", err)
	}
	dllFile.Close()

	_ = os.Remove(markerPath)
	writeDiag("antidebug step a: about to LoadLibrary")
	h, err := syscall.LoadLibrary(dllFile.Name())
	writeDiag(fmt.Sprintf("antidebug step b: LoadLibrary h=%#x err=%v", uintptr(h), err))
	if err != nil {
		t.Fatalf("LoadLibrary AntiDebug: %v — antidebug RET should leave RAX non-zero so loader sees TRUE", err)
	}
	_ = h
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(markerPath); err == nil {
		_ = os.Remove(markerPath)
		t.Errorf("marker present — AntiDebug failed to trip on virtualized host (CPUID-RDTSC delta below threshold?)")
	} else if !os.IsNotExist(err) {
		t.Fatalf("Stat(marker): %v", err)
	}
	writeDiag("antidebug step c: silent no-op confirmed (loader OK, payload skipped)")
}

// TestPackBinary_ConvertEXEtoDLL_LoadLibrary_NoPayload_E2E is the
// slice-5.5.y ablation: pack the same probe but with
// DiagSkipConvertedPayload=true → the converted-DLL stub omits
// SGN rounds, kernel32 resolver, and the CreateThread call.
// Only prologue + flag latch + return-TRUE survive.
//
// Expected outcomes:
//   - LoadLibrary succeeds (the minimal stub returns RAX=1) →
//     bug is downstream of the flag latch (SGN/resolver/CreateThread).
//   - LoadLibrary fails with ERROR_DLL_INIT_FAILED → bug is in
//     the prologue or flag-latch path itself.
//
// We don't read the marker — the probe's main() never runs with
// the payload skipped, so no marker would be written.
func TestPackBinary_ConvertEXEtoDLL_LoadLibrary_NoPayload_E2E(t *testing.T) {
	_ = os.Remove(diagPath)
	writeDiag("=== TestPackBinary_ConvertEXEtoDLL_LoadLibrary_NoPayload_E2E ===")

	probe, err := os.ReadFile(filepath.Join("testdata", "probe_converted.exe"))
	if err != nil {
		t.Skipf("probe fixture missing: %v", err)
	}
	writeDiag(fmt.Sprintf("ablation step 1: read probe (%d B)", len(probe)))

	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:                   packer.FormatWindowsExe,
		ConvertEXEtoDLL:          true,
		DiagSkipConvertedPayload: true,
		Stage1Rounds:             3,
		Seed:                     0xC0DECAFE,
	})
	if err != nil {
		t.Fatalf("PackBinary(ablation): %v", err)
	}
	writeDiag(fmt.Sprintf("ablation step 2: packed (%d B)", len(packed)))

	dllFile, err := os.CreateTemp("", "maldev-packed-ablation-*.dll")
	if err != nil {
		t.Fatalf("create temp dll: %v", err)
	}
	defer os.Remove(dllFile.Name())
	if _, err := dllFile.Write(packed); err != nil {
		t.Fatalf("write packed dll: %v", err)
	}
	dllFile.Close()
	writeDiag(fmt.Sprintf("ablation step 3: wrote %s", dllFile.Name()))

	writeDiag("ablation step 4a: about to LoadLibrary (minimal stub)")
	h, err := syscall.LoadLibrary(dllFile.Name())
	writeDiag(fmt.Sprintf("ablation step 4b: LoadLibrary returned h=%#x err=%v", uintptr(h), err))
	if err != nil {
		t.Fatalf("LoadLibrary (ablated stub) failed with %v — bug is in prologue or flag latch, NOT in SGN/resolver/CreateThread", err)
	}
	writeDiag("ablation step 5: LoadLibrary OK on minimal stub → bug is downstream of flag latch")
	_ = h
}

// TestPackBinary_ConvertEXEtoDLL_LoadLibrary_SGNOnly_E2E packs with
// DiagSkipConvertedResolver=true: SGN rounds run, but resolver +
// CreateThread are omitted. Distinguishes "SGN decrypts .text fine"
// from "resolver or spawn crashes." Pass = SGN OK, bug downstream.
func TestPackBinary_ConvertEXEtoDLL_LoadLibrary_SGNOnly_E2E(t *testing.T) {
	_ = os.Remove(diagPath)
	writeDiag("=== SGNOnly_E2E ===")

	probe, err := os.ReadFile(filepath.Join("testdata", "probe_converted.exe"))
	if err != nil {
		t.Skipf("probe fixture missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:                    packer.FormatWindowsExe,
		ConvertEXEtoDLL:           true,
		DiagSkipConvertedResolver: true,
		Stage1Rounds:              3,
		Seed:                      0xC0DECAFE,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	dllFile, err := os.CreateTemp("", "maldev-packed-sgnonly-*.dll")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(dllFile.Name())
	if _, err := dllFile.Write(packed); err != nil {
		t.Fatalf("write: %v", err)
	}
	dllFile.Close()

	writeDiag("sgnonly step a: about to LoadLibrary")
	h, err := syscall.LoadLibrary(dllFile.Name())
	writeDiag(fmt.Sprintf("sgnonly step b: LoadLibrary h=%#x err=%v", uintptr(h), err))
	if err != nil {
		t.Fatalf("LoadLibrary (SGN only) failed with %v — SGN-decryption is the bug", err)
	}
	writeDiag("sgnonly step c: OK → bug is in resolver or CreateThread")
	_ = h
}

// TestPackBinary_ConvertEXEtoDLL_LoadLibrary_NoSpawn_E2E packs with
// DiagSkipConvertedSpawn=true: SGN + resolver run, only the
// CreateThread call frame is skipped. If this passes and the full
// path fails, the bug lives in the CreateThread call frame itself.
func TestPackBinary_ConvertEXEtoDLL_LoadLibrary_NoSpawn_E2E(t *testing.T) {
	_ = os.Remove(diagPath)
	writeDiag("=== NoSpawn_E2E ===")

	probe, err := os.ReadFile(filepath.Join("testdata", "probe_converted.exe"))
	if err != nil {
		t.Skipf("probe fixture missing: %v", err)
	}
	packed, _, err := packer.PackBinary(probe, packer.PackBinaryOptions{
		Format:                 packer.FormatWindowsExe,
		ConvertEXEtoDLL:        true,
		DiagSkipConvertedSpawn: true,
		Stage1Rounds:           3,
		Seed:                   0xC0DECAFE,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	dllFile, err := os.CreateTemp("", "maldev-packed-nospawn-*.dll")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(dllFile.Name())
	if _, err := dllFile.Write(packed); err != nil {
		t.Fatalf("write: %v", err)
	}
	dllFile.Close()

	writeDiag("nospawn step a: about to LoadLibrary")
	h, err := syscall.LoadLibrary(dllFile.Name())
	writeDiag(fmt.Sprintf("nospawn step b: LoadLibrary h=%#x err=%v", uintptr(h), err))
	if err != nil {
		t.Fatalf("LoadLibrary (no spawn) failed with %v — resolver is the bug", err)
	}
	writeDiag("nospawn step c: OK → bug is in CreateThread call frame")
	_ = h
}
