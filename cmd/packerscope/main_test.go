package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestDetectArtefact_RawBundle pins the canonical raw-bundle path:
// PackBinaryBundle → bytes start with BundleMagic → kindRawBundle.
func TestDetectArtefact_RawBundle(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p")}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	res := detectArtefact(bundle, packer.BundleProfile{})
	if res.Kind != kindRawBundle {
		t.Errorf("Kind = %v, want kindRawBundle", res.Kind)
	}
	if !bytes.Equal(res.Bundle, bundle) {
		t.Errorf("res.Bundle != input")
	}
}

// TestDetectArtefact_LauncherWrapped covers the Go-launcher path:
// launcher prefix + bundle + footer → kindLauncherWrapped.
func TestDetectArtefact_LauncherWrapped(t *testing.T) {
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p")}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	wrapped := packer.AppendBundle(bytes.Repeat([]byte{0x42}, 256), bundle)
	res := detectArtefact(wrapped, packer.BundleProfile{})
	if res.Kind != kindLauncherWrapped {
		t.Errorf("Kind = %v, want kindLauncherWrapped", res.Kind)
	}
	if !bytes.Equal(res.Bundle, bundle) {
		t.Errorf("extracted bundle != original")
	}
}

// TestDetectArtefact_AllAsmWrapped covers the all-asm path: tiny ELF
// with PT_LOAD RWX containing the bundle blob → kindAllAsmWrapped.
// The all-asm wrap path is build-tag-gated to Linux but we can still
// detect it on non-Linux because we're parsing a static ELF byte
// pattern, not running anything.
func TestDetectArtefact_AllAsmWrapped(t *testing.T) {
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p")}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	exe, err := packer.WrapBundleAsExecutableLinuxWithSeed(bundle, packer.BundleProfile{}, 0)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinuxWithSeed: %v", err)
	}
	res := detectArtefact(exe, packer.BundleProfile{})
	if res.Kind != kindAllAsmWrapped {
		t.Errorf("Kind = %v, want kindAllAsmWrapped", res.Kind)
	}
}

// TestDetectArtefact_PerBuildSecretRequiresMatchingProfile confirms a
// per-build wrap is unrecognised under the canonical profile but
// detected once the matching secret-derived profile is supplied —
// the Kerckhoffs property from the defender's seat.
func TestDetectArtefact_PerBuildSecretRequiresMatchingProfile(t *testing.T) {
	profile := packer.DeriveBundleProfile([]byte("op-2026-A"))
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p")}},
		packer.BundleOptions{FixedKey: make([]byte, 16), Profile: profile},
	)
	wrapped := packer.AppendBundleWith(bytes.Repeat([]byte{0xCC}, 256), bundle, profile)

	// Canonical profile → unknown.
	if res := detectArtefact(wrapped, packer.BundleProfile{}); res.Kind != kindUnknown {
		t.Errorf("canonical profile detection = %v, want kindUnknown", res.Kind)
	}
	// Matching profile → detected.
	if res := detectArtefact(wrapped, profile); res.Kind != kindLauncherWrapped {
		t.Errorf("matching-secret detection = %v, want kindLauncherWrapped", res.Kind)
	}
}

// TestDetectArtefact_OpaqueReturnsUnknown asserts random non-bundle
// bytes detect as kindUnknown without panicking.
func TestDetectArtefact_OpaqueReturnsUnknown(t *testing.T) {
	res := detectArtefact([]byte("totally not a bundle"), packer.BundleProfile{})
	if res.Kind != kindUnknown {
		t.Errorf("opaque bytes Kind = %v, want kindUnknown", res.Kind)
	}
}

// TestIsTinyRWXELF distinguishes the tiny-ELF shape from arbitrary
// ELF binaries (e.g. /bin/ls) — used as a heuristic when the magic
// search alone is insufficient.
func TestIsTinyRWXELF(t *testing.T) {
	bundle, _ := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p")}},
		packer.BundleOptions{FixedKey: make([]byte, 16)},
	)
	exe, err := packer.WrapBundleAsExecutableLinuxWithSeed(bundle, packer.BundleProfile{}, 0)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableLinuxWithSeed: %v", err)
	}
	if !isTinyRWXELF(exe) {
		t.Errorf("WrapBundleAsExecutableLinuxWithSeed output not detected as tiny RWX ELF")
	}
	// Non-ELF garbage should fall through.
	if isTinyRWXELF([]byte("not an elf at all")) {
		t.Errorf("non-ELF input falsely detected as tiny RWX ELF")
	}
}

// TestRunExtract_RoundTrip is the defender-side decrypt contract for
// Tier 🟢 #3.2: pack two payloads, hand the bundle file to
// `packerscope extract -out <dir>`, verify both decrypted files
// round-trip byte-identical to the originals. This is the
// pedagogical inverse of `cmd/packer bundle -pl …` — the wire
// format is genuinely public and the per-payload XOR keys live
// inside each FingerprintEntry, so any defender holding the bundle
// can decrypt without further secrets.
func TestRunExtract_RoundTrip(t *testing.T) {
	pA := []byte("payload-zero-content-AAA")
	pB := []byte("payload-one-content-BBB")
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{
			{Binary: pA},
			{Binary: pB},
		},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	dir := t.TempDir()
	src := dir + "/bundle.bin"
	if err := os.WriteFile(src, bundle, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	outDir := dir + "/out"
	if rc := runExtract([]string{"-out", outDir, src}); rc != 0 {
		t.Fatalf("runExtract returned %d, want 0", rc)
	}

	got0, err := os.ReadFile(outDir + "/payload-00.bin")
	if err != nil {
		t.Fatalf("read payload-00: %v", err)
	}
	got1, err := os.ReadFile(outDir + "/payload-01.bin")
	if err != nil {
		t.Fatalf("read payload-01: %v", err)
	}
	if !bytes.Equal(got0, pA) {
		t.Errorf("payload-00: got %q, want %q", got0, pA)
	}
	if !bytes.Equal(got1, pB) {
		t.Errorf("payload-01: got %q, want %q", got1, pB)
	}
}

// TestRunExtract_SecretRoundTrip mirrors the canonical round-trip
// for a per-build wrap: operator packs with `-secret S`, defender
// supplies the SAME secret to extract. Without it, detection
// returns kindUnknown and extract bails out (covered separately
// by TestDetectArtefact_PerBuildSecretRequiresMatchingProfile).
func TestRunExtract_SecretRoundTrip(t *testing.T) {
	const secret = "operator-team-2026-04"
	profile := packer.DeriveBundleProfile([]byte(secret))
	payload := []byte("the answer is 42 and other deep truths")
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: payload}},
		packer.BundleOptions{Profile: profile},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	dir := t.TempDir()
	src := dir + "/bundle-secret.bin"
	if err := os.WriteFile(src, bundle, 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}

	outDir := dir + "/out"
	if rc := runExtract([]string{"-secret", secret, "-out", outDir, src}); rc != 0 {
		t.Fatalf("runExtract returned %d, want 0", rc)
	}
	got, err := os.ReadFile(outDir + "/payload-00.bin")
	if err != nil {
		t.Fatalf("read payload-00: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload-00: got %q, want %q", got, payload)
	}

	// Negative path: wrong secret → kindUnknown → non-zero exit.
	wrongDir := dir + "/wrong"
	if rc := runExtract([]string{"-secret", "wrong-secret", "-out", wrongDir, src}); rc == 0 {
		t.Errorf("runExtract with wrong secret returned 0 (want non-zero)")
	}
}
