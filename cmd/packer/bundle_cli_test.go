package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestParseBundleSpec_Vendors covers the four vendor recipes
// (intel/amd/wildcard/empty) and verifies the resulting predicate
// bitmask + VendorString reflect the spec's intent.
func TestParseBundleSpec_Vendors(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.bin")
	if err := os.WriteFile(src, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	cases := []struct {
		spec       string
		wantVendor string
		wantBits   uint8
	}{
		{src + ":intel:22000-99999", "GenuineIntel", packer.PTCPUIDVendor | packer.PTWinBuild},
		{src + ":amd:10000-19999", "AuthenticAMD", packer.PTCPUIDVendor | packer.PTWinBuild},
		{src + ":*:*-*", "", packer.PTMatchAll},
		{src + ":intel:*-*", "GenuineIntel", packer.PTCPUIDVendor},
	}
	for _, c := range cases {
		t.Run(c.spec, func(t *testing.T) {
			bp, err := parseBundleSpec(c.spec)
			if err != nil {
				t.Fatalf("parseBundleSpec: %v", err)
			}
			if bp.Fingerprint.PredicateType != c.wantBits {
				t.Errorf("PredicateType = %#x, want %#x", bp.Fingerprint.PredicateType, c.wantBits)
			}
			got := strings.TrimRight(string(bp.Fingerprint.VendorString[:]), "\x00")
			if got != c.wantVendor {
				t.Errorf("VendorString = %q, want %q", got, c.wantVendor)
			}
		})
	}
}

// TestParseBundleSpec_Errors covers the four malformed-spec error
// paths: missing parts, unknown vendor, unparseable build numbers,
// missing payload file.
func TestParseBundleSpec_Errors(t *testing.T) {
	cases := []string{
		"toofew",                          // missing colons
		"f.bin:martian:0-0",               // unknown vendor
		"/nonexistent:intel:0-0",          // missing payload
		"f.bin:intel:abc-def",             // un-parseable build
		"f.bin:intel:0-99999:bogus",       // unknown trailing keyword
	}
	for _, spec := range cases {
		if _, err := parseBundleSpec(spec); err == nil {
			t.Errorf("spec %q: expected error, got nil", spec)
		}
	}
}

// TestParseBundleSpec_NegateFlag covers the v0.88.0 spec extension:
// optional `:negate` trailing suffix flips the predicate.
func TestParseBundleSpec_NegateFlag(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "p.bin")
	if err := os.WriteFile(src, []byte("hi"), 0o644); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	cases := []struct {
		name       string
		spec       string
		wantNegate bool
	}{
		{"no suffix", src + ":intel:0-99999", false},
		{"negate suffix", src + ":intel:0-99999:negate", true},
		{"empty trailing", src + ":intel:0-99999:", false},
		{"negate on wildcard", src + ":*:*-*:negate", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bp, err := parseBundleSpec(c.spec)
			if err != nil {
				t.Fatalf("parseBundleSpec %q: %v", c.spec, err)
			}
			if got := bp.Fingerprint.Negate; got != c.wantNegate {
				t.Errorf("Negate = %v, want %v", got, c.wantNegate)
			}
		})
	}
}
