//go:build linux

package packer_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// exit42Shellcode mirrors the fixture used by transform's minimal-ELF
// test — same 12-byte exit(42) sequence so the all-asm path can prove
// itself with a payload that has no PE/ELF headers (the stub jumps
// into raw shellcode after decrypt).
var exit42Shellcode = []byte{
	0x31, 0xff,                   // xor edi, edi
	0x40, 0xb7, 0x2a,             // mov dil, 42
	0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
	0x0f, 0x05,                   // syscall
}

// TestWrapBundleAsExecutableLinux_RejectsBadInputs covers the two
// fast-path validation errors WrapBundleAsExecutableLinux surfaces
// before delegating to BuildMinimalELF64.
func TestWrapBundleAsExecutableLinux_RejectsBadInputs(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		_, err := packer.WrapBundleAsExecutableLinux([]byte{0x4D, 0x4C})
		if !errors.Is(err, packer.ErrBundleTruncated) {
			t.Errorf("err = %v, want ErrBundleTruncated", err)
		}
	})
	t.Run("badMagic", func(t *testing.T) {
		bogus := make([]byte, 64)
		_, err := packer.WrapBundleAsExecutableLinux(bogus)
		if !errors.Is(err, packer.ErrBundleBadMagic) {
			t.Errorf("err = %v, want ErrBundleBadMagic", err)
		}
	})
}

// TestWrapBundleAsExecutableLinux_ScanFallsThrough exercises the
// stub's fingerprint-loop semantics: the first entry has a vendor
// predicate the host can't match (PTCPUIDVendor with a nonsense
// vendor string and no PT_MATCH_ALL bit), so the stub must walk past
// it and pick the second entry (PTMatchAll).
//
// This proves the scan-loop dispatch — not just always-idx-0 — even
// without the per-entry vendor compare wired into the stub yet:
// today's predicate test is "PT_MATCH_ALL bit set", so an entry with
// only PTCPUIDVendor set deliberately fails the test and gets
// skipped. Vendor-aware predicate evaluation lands in a follow-up
// commit; this test will continue to pass when that ships.
func TestWrapBundleAsExecutableLinux_ScanFallsThrough(t *testing.T) {
	// First payload: irrelevant data + PTCPUIDVendor (without
	// PTMatchAll) → fails the loop's match test → skipped.
	//
	// Second payload: exit42 shellcode + PTMatchAll → fires.
	bogus := [12]byte{'N', 'o', 't', 'A', 'R', 'e', 'a', 'l', 'C', 'P', 'U', '!'}
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{
			{
				Binary: []byte("decoy"),
				Fingerprint: packer.FingerprintPredicate{
					PredicateType: packer.PTCPUIDVendor,
					VendorString:  bogus,
				},
			},
			{
				Binary: exit42Shellcode,
				Fingerprint: packer.FingerprintPredicate{
					PredicateType: packer.PTMatchAll,
				},
			},
		},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinux: %v", err)
	}
	if len(wrapped) >= 4096 {
		t.Errorf("wrapped binary = %d bytes, want < 4096", len(wrapped))
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "scan-bundle")
	if err := os.WriteFile(exe, wrapped, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (not an ExitError)", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %d, want 42 (scan should pick payload 1)", got)
	}
	t.Logf("scan-loop bundle: %d bytes; idx 0 skipped, idx 1 fired → exit=42", len(wrapped))
}

// TestWrapBundleAsExecutableLinux_NoMatchExitsCleanly exercises the
// stub's no-match fallback: a 1-payload bundle with a vendor
// predicate the host can't satisfy and no PT_MATCH_ALL fallback
// should reach the stub's `mov eax, 231 ; xor edi, edi ; syscall`
// tail and exit cleanly with code 0.
func TestWrapBundleAsExecutableLinux_NoMatchExitsCleanly(t *testing.T) {
	bogus := [12]byte{'N', 'o', 't', 'A', 'R', 'e', 'a', 'l', 'C', 'P', 'U', '!'}
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42Shellcode,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTCPUIDVendor,
				VendorString:  bogus,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinux: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "nomatch-bundle")
	if err := os.WriteFile(exe, wrapped, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := exec.CommandContext(ctx, exe).Run(); err != nil {
		t.Errorf("expected exit 0 (no-match fallback), got %v", err)
	}
}

// TestWrapBundleAsExecutableLinux_PolymorphicAcrossPacks is the
// polymorphism gate: two consecutive packs of the same bundle must
// produce wrapped binaries with DIFFERENT byte sequences in the stub
// region (Intel multi-byte NOPs spliced at random per-pack), but
// BOTH must run to exit 42.
//
// Defenders writing yara on stub bytes can no longer cluster
// individual packs even within a single deployment.
func TestWrapBundleAsExecutableLinux_PolymorphicAcrossPacks(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42Shellcode,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		// FixedKey makes the bundle bytes themselves identical across
		// the two packs — only the stub junk differs.
		packer.BundleOptions{FixedKey: bytes.Repeat([]byte{0x42}, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	a, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("Wrap a: %v", err)
	}
	b, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("Wrap b: %v", err)
	}

	if bytes.Equal(a, b) {
		t.Fatal("two consecutive Wrap calls produced identical bytes — junk randomisation broken")
	}

	// Compare the stub region (bytes 120..200) — they MUST differ.
	stubA := a[transform.MinimalELF64HeadersSize:transform.MinimalELF64HeadersSize+200]
	stubB := b[transform.MinimalELF64HeadersSize:transform.MinimalELF64HeadersSize+200]
	if bytes.Equal(stubA, stubB) {
		t.Errorf("stub regions identical across packs — polymorphism broken")
	}

	// Both must run to exit 42.
	dir := t.TempDir()
	for i, blob := range [][]byte{a, b} {
		exe := filepath.Join(dir, fmt.Sprintf("poly-%d", i))
		if err := os.WriteFile(exe, blob, 0o755); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := exec.CommandContext(ctx, exe).Run()
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("pack %d run: %v (junk-injected stub crashed)", i, err)
		}
		if got := exitErr.ExitCode(); got != 42 {
			t.Errorf("pack %d exit = %d, want 42", i, got)
		}
	}
	t.Logf("two packs: %d B vs %d B; stub bytes differ; both exit=42",
		len(a), len(b))
}

// TestWrapBundleAsExecutableLinuxWithSeed_DeterministicAcrossSameSeed
// is the inverse pin: the same seed MUST produce byte-identical
// output. Used by reproducible-build operators and by golden-file
// regression tests.
func TestWrapBundleAsExecutableLinuxWithSeed_DeterministicAcrossSameSeed(t *testing.T) {
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary:      exit42Shellcode,
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll},
		}},
		packer.BundleOptions{FixedKey: bytes.Repeat([]byte{0xAB}, 16)},
	)

	a, err := packer.WrapBundleAsExecutableLinuxWithSeed(bundle, packer.BundleProfile{}, 12345)
	if err != nil {
		t.Fatalf("Wrap a: %v", err)
	}
	b, err := packer.WrapBundleAsExecutableLinuxWithSeed(bundle, packer.BundleProfile{}, 12345)
	if err != nil {
		t.Fatalf("Wrap b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("same seed produced different bytes — determinism broken")
	}

	// Different seed → different bytes.
	c, _ := packer.WrapBundleAsExecutableLinuxWithSeed(bundle, packer.BundleProfile{}, 99999)
	if bytes.Equal(a, c) {
		t.Errorf("different seeds produced same bytes — junk size insensitive to seed")
	}
}

// TestWrapBundleAsExecutableLinuxWith_PerBuildSecretRoundTrip is the
// Kerckhoffs gate for the all-asm wrap path. The bundle stub asm
// reads only count + fpOff + plOff from the header, never the magic
// — so per-build magic bytes pass through the runtime evaluator
// transparently. This test pins:
//
//   - WrapBundleAsExecutableLinuxWith accepts a bundle whose magic
//     was set by a per-build BundleOptions.Profile and produces a
//     runnable ELF.
//   - The ELF runs to exit 42 (proving the stub doesn't accidentally
//     check for the canonical magic).
//   - The canonical WrapBundleAsExecutableLinux REJECTS the same
//     per-build bundle with ErrBundleBadMagic.
func TestWrapBundleAsExecutableLinuxWith_PerBuildSecretRoundTrip(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("allasm-deploy-A"))
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42Shellcode,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{Profile: profile},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped, err := packer.WrapBundleAsExecutableLinuxWith(bundle, profile)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinuxWith: %v", err)
	}
	if len(wrapped) >= 4096 {
		t.Errorf("wrapped binary = %d bytes, want < 4096", len(wrapped))
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "perbuild-bundle")
	if err := os.WriteFile(exe, wrapped, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (per-build wrap didn't dispatch)", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("per-build wrap exit code = %d, want 42", got)
	}
	t.Logf("per-build all-asm bundle: %d bytes; magic=%#x → exit=42",
		len(wrapped), profile.Magic)

	// Negative: canonical wrap must reject the per-build bundle.
	if _, err := packer.WrapBundleAsExecutableLinux(bundle); !errors.Is(err, packer.ErrBundleBadMagic) {
		t.Errorf("canonical Wrap on per-build bundle: err = %v, want ErrBundleBadMagic", err)
	}
}

// TestWrapBundleAsExecutableLinux_VendorAwareDispatch proves the
// vendor-aware predicate evaluation in the scan loop: the bundle has
// TWO PTCPUIDVendor entries — one targeting a bogus vendor (decoy)
// and one targeting the actual host CPU vendor. The stub must run the
// CPUID prologue, walk both entries, do a 12-byte VendorString
// compare against the host, fail the first entry, succeed on the
// second, and dispatch to the second payload (exit42 shellcode).
//
// This is the test that distinguishes the vendor-aware stub from
// the prior 'first PT_MATCH_ALL wins' baseline. If it passes, the
// CPUID setup and the 12-byte compare logic are wired correctly.
func TestWrapBundleAsExecutableLinux_VendorAwareDispatch(t *testing.T) {
	hostVendor := packer.HostCPUIDVendor()
	if hostVendor == ([12]byte{}) {
		t.Skip("HostCPUIDVendor returned zero — non-x86 build agent?")
	}

	bogus := [12]byte{'N', 'o', 't', 'A', 'R', 'e', 'a', 'l', 'C', 'P', 'U', '!'}
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{
			{
				Binary: []byte("decoy-payload-shouldnt-fire"),
				Fingerprint: packer.FingerprintPredicate{
					PredicateType: packer.PTCPUIDVendor,
					VendorString:  bogus,
				},
			},
			{
				Binary: exit42Shellcode,
				Fingerprint: packer.FingerprintPredicate{
					PredicateType: packer.PTCPUIDVendor,
					VendorString:  hostVendor,
				},
			},
		},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinux: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "vendor-bundle")
	if err := os.WriteFile(exe, wrapped, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (not an ExitError; vendor-aware dispatch crashed)", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %d, want 42 (host-vendor entry should fire)", got)
	}
	t.Logf("vendor-aware bundle: %d bytes; host=%q matched idx 1 → exit=42",
		len(wrapped), string(hostVendor[:]))
}

// TestWrapBundleAsExecutableLinux_VendorWildcard verifies that an
// all-zero VendorString in a PTCPUIDVendor entry acts as a wildcard
// (matches any host).
func TestWrapBundleAsExecutableLinux_VendorWildcard(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42Shellcode,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTCPUIDVendor,
				// VendorString left zero → wildcard
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinux: %v", err)
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "wildcard-bundle")
	if err := os.WriteFile(exe, wrapped, 0o755); err != nil {
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
		t.Errorf("wildcard bundle exit = %d, want 42", got)
	}
}

// TestWrapBundleAsExecutableLinux_RunsExit42 is the SHIP GATE for the
// all-asm bundle path. It exercises every layer:
//
//   - PackBinaryBundle wraps a 1-payload bundle around the exit42
//     shellcode (PTMatchAll predicate so every host fires payload 0).
//   - WrapBundleAsExecutableLinux emits the stub asm, patches its
//     RIP-relative bundle-offset immediate, concatenates stub + bundle,
//     and feeds the result to BuildMinimalELF64.
//   - The result lands as 0o755 on disk; the kernel maps the single
//     PT_LOAD RWX, jumps to the stub at vaddr+120.
//   - The stub resolves the bundle base via call/pop PIC, locates
//     PayloadEntry[0] from the wire-format header, XOR-decrypts the
//     data in place using the 16-byte rolling key, and JMPs to it.
//   - The decrypted bytes are exit42 shellcode → process exits 42.
//
// Asserts: exit code == 42, AND total binary size < 4 KiB (the
// elevation plan's stated goal — bundle binary that fits a "pretty
// poster"). Today's measurement: ~330 bytes (120 ELF header + 73 stub
// + 32 BundleHeader + 48 FingerprintEntry + 32 PayloadEntry + 12
// payload + 16 key … plus encryption overhead).
func TestWrapBundleAsExecutableLinux_RunsExit42(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: exit42Shellcode,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	wrapped, err := packer.WrapBundleAsExecutableLinux(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinux: %v", err)
	}
	if len(wrapped) >= 4096 {
		t.Errorf("wrapped binary = %d bytes, want < 4096 (4 KiB target)", len(wrapped))
	}

	dir := t.TempDir()
	exe := filepath.Join(dir, "tiny-bundle")
	if err := os.WriteFile(exe, wrapped, 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = exec.CommandContext(ctx, exe).Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("run %q: %v (not an ExitError; bundle didn't dispatch)", exe, err)
	}
	if got := exitErr.ExitCode(); got != 42 {
		t.Errorf("exit code = %d, want 42", got)
	}

	t.Logf("all-asm bundle: %d bytes total → exit=42", len(wrapped))
}
