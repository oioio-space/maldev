package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestBundleCLI_PackInspectMatch_RoundTrip exercises the three bundle
// verbs by return code + on-disk state:
//   - runBundle pack: 2 payloads → bundle file written
//   - runBundleInspect: rc=0 on a valid bundle
//   - runBundleMatch: rc=0; resolved index verified separately via
//     [packer.MatchBundleHost] so the test is independent of stdout
//     capture quirks.
//
// Stdout/stderr capture proved fragile (pipe ordering vs goroutine
// scheduling); asserting structural state instead — the bundle blob
// can be re-parsed from disk via [packer.InspectBundle], which is the
// same path the CLI's `-inspect` verb uses internally.
func TestBundleCLI_PackInspectMatch_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "p1.bin")
	p2 := filepath.Join(dir, "p2.bin")
	bundle := filepath.Join(dir, "bundle.bin")
	if err := os.WriteFile(p1, []byte("targeted-payload-bytes"), 0o644); err != nil {
		t.Fatalf("write p1: %v", err)
	}
	if err := os.WriteFile(p2, bytes.Repeat([]byte{0xCC}, 64), 0o644); err != nil {
		t.Fatalf("write p2: %v", err)
	}

	if rc := runBundle([]string{
		"-out", bundle,
		"-pl", p1 + ":*:*-*",
		"-pl", p2 + ":*:*-*",
	}); rc != 0 {
		t.Fatalf("runBundle pack rc = %d", rc)
	}

	blob, err := os.ReadFile(bundle)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	info, err := packer.InspectBundle(blob)
	if err != nil {
		t.Fatalf("InspectBundle: %v", err)
	}
	if info.Magic != packer.BundleMagic {
		t.Errorf("Magic = %#x, want %#x", info.Magic, packer.BundleMagic)
	}
	if info.Count != 2 {
		t.Errorf("Count = %d, want 2", info.Count)
	}

	if rc := runBundleInspect(bundle); rc != 0 {
		t.Errorf("runBundleInspect rc = %d, want 0", rc)
	}
	if rc := runBundleMatch(bundle); rc != 0 {
		t.Errorf("runBundleMatch rc = %d, want 0", rc)
	}

	// And confirm the wildcard fallthrough resolves to the first entry.
	idx, err := packer.MatchBundleHost(blob)
	if err != nil {
		t.Fatalf("MatchBundleHost: %v", err)
	}
	if idx != 0 {
		t.Errorf("MatchBundleHost = %d, want 0 (wildcard-first)", idx)
	}
}

// TestBundleCLI_InspectRejectsNonBundle confirms inspect returns rc=1
// (non-zero) when fed a file that is not a bundle, without panicking.
func TestBundleCLI_InspectRejectsNonBundle(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "not-a-bundle.bin")
	if err := os.WriteFile(bogus, []byte("ELF\x7f garbage"), 0o644); err != nil {
		t.Fatalf("write bogus: %v", err)
	}
	if rc := runBundleInspect(bogus); rc != 1 {
		t.Errorf("runBundleInspect non-bundle rc = %d, want 1", rc)
	}
}

// TestBundleCLI_MatchRejectsNonBundle: same shape for the match verb.
func TestBundleCLI_MatchRejectsNonBundle(t *testing.T) {
	dir := t.TempDir()
	bogus := filepath.Join(dir, "not-a-bundle.bin")
	if err := os.WriteFile(bogus, []byte("not-a-bundle"), 0o644); err != nil {
		t.Fatalf("write bogus: %v", err)
	}
	if rc := runBundleMatch(bogus); rc != 1 {
		t.Errorf("runBundleMatch non-bundle rc = %d, want 1", rc)
	}
}
