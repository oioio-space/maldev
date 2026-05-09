//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
)

// shellcodeExit42 is a tiny static-PIE x86-64 ELF that exits with
// code 42. Pre-built and committed under testdata/ so the test does
// not depend on a system gcc/ld being available. Built with:
//
//	cat > /tmp/exit42.s <<'EOF'
//	.intel_syntax noprefix
//	.global _start
//	_start:
//	    mov rax, 60
//	    mov rdi, 42
//	    syscall
//	EOF
//	as -o /tmp/exit42.o /tmp/exit42.s
//	ld -static -pie -nostdlib --no-dynamic-linker -e _start \
//	   --no-eh-frame-hdr -o /tmp/exit42 /tmp/exit42.o
//
// We avoid committing the binary by generating it inline at test
// startup if `as`+`ld` are available; otherwise we skip.
func buildExit42(t *testing.T) []byte {
	t.Helper()
	if _, err := exec.LookPath("as"); err != nil {
		t.Skip("`as` not in PATH — install binutils to run the launcher E2E")
	}
	if _, err := exec.LookPath("ld"); err != nil {
		t.Skip("`ld` not in PATH")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "exit42.s")
	obj := filepath.Join(dir, "exit42.o")
	bin := filepath.Join(dir, "exit42")
	if err := os.WriteFile(src, []byte(
		".intel_syntax noprefix\n.global _start\n_start:\nmov rax, 60\nmov rdi, 42\nsyscall\n",
	), 0o644); err != nil {
		t.Fatalf("write asm: %v", err)
	}
	if out, err := exec.Command("as", "-o", obj, src).CombinedOutput(); err != nil {
		t.Fatalf("as: %v: %s", err, out)
	}
	if out, err := exec.Command("ld", "-static", "-pie", "-nostdlib",
		"--no-dynamic-linker", "-e", "_start", "-o", bin, obj).CombinedOutput(); err != nil {
		t.Fatalf("ld: %v: %s", err, out)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read exit42: %v", err)
	}
	return data
}

// TestLauncher_E2E_FallbackFirstSelectsIdx0 verifies BundleFallbackFirst:
// when no predicate matches but FallbackBehaviour=BundleFallbackFirst,
// the launcher executes payload 0 anyway. We force "no match" by giving
// the only payload an impossible vendor predicate.
func TestLauncher_E2E_FallbackFirstSelectsIdx0(t *testing.T) {
	exit42 := buildExit42(t)

	bogus := [12]byte{'N', 'o', 't', 'A', 'R', 'e', 'a', 'l', 'C', 'P', 'U', '!'}
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTCPUIDVendor,
				VendorString:  bogus,
			},
		}},
		packer.BundleOptions{FallbackBehaviour: packer.BundleFallbackFirst},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	dir := t.TempDir()
	launcher := filepath.Join(dir, "bundle-launcher")
	if out, err := exec.Command("go", "build", "-o", launcher,
		"github.com/oioio-space/maldev/cmd/bundle-launcher").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	launcherBytes, _ := os.ReadFile(launcher)
	wrapped := packer.AppendBundle(launcherBytes, bundle)
	wrappedPath := filepath.Join(dir, "app")
	if err := os.WriteFile(wrappedPath, wrapped, 0o755); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, wrappedPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("exec: %v (not an ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("FallbackFirst exit code = %d, want 42", got)
	}
}

// TestLauncher_E2E_FallbackExitOnNoMatch verifies the default
// BundleFallbackExit behaviour: no predicate match → silent exit 0,
// no payload executed.
func TestLauncher_E2E_FallbackExitOnNoMatch(t *testing.T) {
	exit42 := buildExit42(t)

	bogus := [12]byte{'N', 'o', 't', 'A', 'R', 'e', 'a', 'l', 'C', 'P', 'U', '!'}
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTCPUIDVendor,
				VendorString:  bogus,
			},
		}},
		packer.BundleOptions{FallbackBehaviour: packer.BundleFallbackExit},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	dir := t.TempDir()
	launcher := filepath.Join(dir, "bundle-launcher")
	if out, err := exec.Command("go", "build", "-o", launcher,
		"github.com/oioio-space/maldev/cmd/bundle-launcher").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	launcherBytes, _ := os.ReadFile(launcher)
	wrapped := packer.AppendBundle(launcherBytes, bundle)
	wrappedPath := filepath.Join(dir, "app")
	if err := os.WriteFile(wrappedPath, wrapped, 0o755); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, wrappedPath).Run(); err != nil {
		t.Errorf("FallbackExit: expected exit 0, got %v", err)
	}
}

// TestLauncher_E2E_PerBuildSecret_PairsCorrectly is the Kerckhoffs
// E2E gate. The launcher and the bundle wrap MUST share the same
// per-build secret for the launcher to find its bundle:
//
//   - Build the launcher with -ldflags '-X main.bundleSecret=<S>'
//   - Pack a bundle and wrap with the SAME secret S
//   - Run wrapped binary → exit 42 (per-build pair works)
//
// The smoking-gun negative side:
//
//   - Build a launcher with secret A
//   - Wrap a bundle with secret B
//   - Run → launcher's ExtractBundleWith fails with ErrBundleBadMagic
//     and the launcher exits non-zero (NOT 42).
//
// This proves Kerckhoffs in practice: the wire format is public; only
// the secret distinguishes individual builds.
func TestLauncher_E2E_PerBuildSecret_PairsCorrectly(t *testing.T) {
	exit42 := buildExit42(t)
	const secret = "ops-cycle-2026-05-target-deploy"

	dir := t.TempDir()
	launcher := filepath.Join(dir, "bundle-launcher-secret")
	if out, err := exec.Command("go", "build",
		"-ldflags", "-X main.bundleSecret="+secret,
		"-o", launcher,
		"github.com/oioio-space/maldev/cmd/bundle-launcher",
	).CombinedOutput(); err != nil {
		t.Fatalf("go build with secret ldflag: %v: %s", err, out)
	}
	launcherBytes, err := os.ReadFile(launcher)
	if err != nil {
		t.Fatalf("read launcher: %v", err)
	}

	profile := packer.DeriveBundleProfile([]byte(secret))
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{Profile: profile},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped := packer.AppendBundleWith(launcherBytes, bundle, profile)
	wrappedPath := filepath.Join(dir, "app-secret")
	if err := os.WriteFile(wrappedPath, wrapped, 0o755); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, wrappedPath).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("paired-secret run: %v (expected ExitError exit 42)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("paired secret exit = %d, want 42", got)
	}

	// Negative case: wrap with a DIFFERENT secret. The launcher's
	// ExtractBundleWith call should fail to find a valid footer.
	wrongProfile := packer.DeriveBundleProfile([]byte("wrong-secret"))
	wrongBundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{Profile: wrongProfile},
	)
	wrongWrapped := packer.AppendBundleWith(launcherBytes, wrongBundle, wrongProfile)
	wrongPath := filepath.Join(dir, "app-mismatched")
	if err := os.WriteFile(wrongPath, wrongWrapped, 0o755); err != nil {
		t.Fatalf("write wrong-wrapped: %v", err)
	}

	err = exec.CommandContext(ctx, wrongPath).Run()
	exitErr, ok = err.(*exec.ExitError)
	if !ok {
		t.Fatalf("mismatched-secret run: %v (expected ExitError, got nil or non-exit)", err)
	}
	if got := exitErr.ExitCode(); got == 42 {
		t.Errorf("mismatched secret unexpectedly exited 42 — magic gate broken")
	}
	t.Logf("mismatched-secret rejected by launcher with exit code %d (expected non-42)",
		exitErr.ExitCode())
}

// TestLauncher_E2E_WrapAndRun is the C6 ship gate: builds the launcher,
// packs a bundle around a tiny `exit 42` payload, wraps the bundle into
// the launcher via packer.AppendBundle, executes the result, asserts
// exit code == 42. End-to-end: every layer (PackBinaryBundle →
// AppendBundle → ExtractBundle → MatchBundleHost → UnpackBundle →
// memfd_create execve) participates.
func TestLauncher_E2E_WrapAndRun(t *testing.T) {
	exit42 := buildExit42(t)

	// Pack a 1-payload bundle with PT_MATCH_ALL — wildcard fires on
	// any host, which keeps the test independent of the build agent's
	// CPU vendor.
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	// Build the launcher (`go build` against the same package the test
	// is in — circular but go test handles it). Use a tempdir so we
	// don't pollute the repo.
	dir := t.TempDir()
	launcher := filepath.Join(dir, "bundle-launcher")
	cmd := exec.Command("go", "build", "-o", launcher,
		"github.com/oioio-space/maldev/cmd/bundle-launcher")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}

	launcherBytes, err := os.ReadFile(launcher)
	if err != nil {
		t.Fatalf("read launcher: %v", err)
	}

	// Wrap the bundle.
	wrapped := packer.AppendBundle(launcherBytes, bundle)
	wrappedPath := filepath.Join(dir, "app")
	if err := os.WriteFile(wrappedPath, wrapped, 0o755); err != nil {
		t.Fatalf("write wrapped: %v", err)
	}

	// Execute and assert exit code.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	run := exec.CommandContext(ctx, wrappedPath)
	err = run.Run()
	if err == nil {
		t.Fatalf("wrapped binary exited 0, want 42")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("wrapped exec: %v (not an ExitError)", err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("wrapped exit code = %d, want 42 (stderr: %q)",
			got, strings.TrimSpace(string(exitErr.Stderr)))
	}
}
