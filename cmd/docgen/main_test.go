package main

import (
	"reflect"
	"strings"
	"testing"
)

func TestFirstSentence(t *testing.T) {
	cases := map[string]string{
		"":                                          "",
		"Package foo bar baz.\nMore.":               "bar baz",
		"Package amsi patches AmsiScanBuffer.":      "patches AmsiScanBuffer",
		"Package x y. z.":                           "y",
		"some prose without Package prefix.":        "some prose without Package prefix",
		// No sentence-ending period — first-paragraph fallback returns the
		// remainder after stripping "Package <name> ".
		"Package no period":                         "period",
		"Package cert generates self-signed X.509 certificates.": "generates self-signed X.509 certificates",
		"Package x version 1.2.3.4 spans dots.":     "version 1.2.3.4 spans dots",
	}
	for in, want := range cases {
		if got := firstSentence(in); got != want {
			t.Errorf("firstSentence(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMITRE(t *testing.T) {
	doc := `Package x patches things.

# MITRE ATT&CK

  - T1003.001 (LSASS Memory)
  - T1562.001 (Disable Tools)

# Detection level

quiet
`
	got := parseMITRE(doc)
	want := []string{"T1003.001", "T1562.001"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseMITRE = %v, want %v", got, want)
	}

	// No MITRE section -> empty.
	if got := parseMITRE("plain prose"); len(got) != 0 {
		t.Errorf("expected no IDs, got %v", got)
	}

	// Dedup + sort.
	dup := "# MITRE ATT&CK\n  - T1055\n  - T1055\n  - T1055.012\n"
	got2 := parseMITRE(dup)
	want2 := []string{"T1055", "T1055.012"}
	if !reflect.DeepEqual(got2, want2) {
		t.Errorf("parseMITRE dedup = %v, want %v", got2, want2)
	}
}

func TestParseDetectionLevel(t *testing.T) {
	cases := map[string]string{
		"":                                 "",
		"# Detection level\n\nvery-quiet\n": "very-quiet",
		"# Detection level\n\nquiet":        "quiet",
		"# Detection level\n\nnoisy\n\nbla": "noisy",
		"no detection section here":        "",
	}
	for in, want := range cases {
		if got := parseDetectionLevel(in); got != want {
			t.Errorf("parseDetectionLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReplaceBlock(t *testing.T) {
	src := `prefix
<!-- BEGIN AUTOGEN: x -->
old content
<!-- END AUTOGEN: x -->
suffix
`
	got := replaceBlock(src, "<!-- BEGIN AUTOGEN: x -->", "<!-- END AUTOGEN: x -->", "new content")
	if !strings.Contains(got, "new content") {
		t.Errorf("missing new content: %s", got)
	}
	if strings.Contains(got, "old content") {
		t.Errorf("old content not replaced: %s", got)
	}
	// Unchanged when markers absent.
	noMarkers := "no markers here"
	if got := replaceBlock(noMarkers, "<!-- BEGIN AUTOGEN: x -->", "<!-- END AUTOGEN: x -->", "new"); got != noMarkers {
		t.Errorf("unchanged when markers absent: got %q", got)
	}
}

func TestFilterPublic(t *testing.T) {
	in := []PackageDoc{
		{RelativePath: "cleanup/ads"},
		{RelativePath: "internal/krb5/types"},
		{RelativePath: "scripts/x64dbg-harness/inject"},
		{RelativePath: "cmd/rshell"},
		{RelativePath: "."},
		{RelativePath: "pe/masquerade/preset/cmd"},
		{RelativePath: "pe/masquerade/internal/gen"},
		{RelativePath: "testutil"},
		{RelativePath: "testutil/clrhost"},
		{RelativePath: "evasion/amsi"},
	}
	out := filterPublic(in)
	want := []string{"cleanup/ads", "evasion/amsi"}
	got := []string{}
	for _, p := range out {
		got = append(got, p.RelativePath)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterPublic = %v, want %v", got, want)
	}
}

func TestCollapseWhitespace(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"   \n\n  ":                       "",
		"a b c":                           "a b c",
		"a   b\n c":                       "a b c",
		"line one\nline two\n\tline three": "line one line two line three",
		"  trim  edges  ":                 "trim edges",
	}
	for in, want := range cases {
		if got := collapseWhitespace(in); got != want {
			t.Errorf("collapseWhitespace(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstSentence_CollapsesNewlines(t *testing.T) {
	// Reproduces the prior bug: word-wrapped doc.go comments produced
	// summaries with embedded newlines that broke markdown table cells.
	in := "Package x provides a long\n description that wraps\n  across lines. More."
	want := "provides a long description that wraps across lines"
	if got := firstSentence(in); got != want {
		t.Errorf("firstSentence wrapped: got %q, want %q", got, want)
	}
}

func TestFirstSentence_LeadInColon(t *testing.T) {
	// Reproduces the pe/strip bug: doc.go intro that ends with ':' and
	// is followed by a bullet list previously bled into the summary.
	// Now the first-paragraph cap stops the cut before the bullets.
	in := `Package strip sanitises Go-built PE binaries by removing
toolchain artefacts that fingerprint the producer:

  - The Go pclntab (Go 1.16+ magic bytes) — wiped, breaking
    redress, GoReSym, and IDA's "go_parser" plugin.`
	want := "sanitises Go-built PE binaries by removing toolchain artefacts that fingerprint the producer"
	if got := firstSentence(in); got != want {
		t.Errorf("firstSentence lead-in colon: got %q, want %q", got, want)
	}
}

func TestNormalizeDetectionLevel(t *testing.T) {
	cases := map[string]string{
		"":           "—",
		"very-quiet": "very-quiet",
		"quiet":      "quiet",
		"moderate":   "moderate",
		"noisy":      "noisy",
		"very-noisy": "very-noisy",
		"Quiet":      "quiet",  // case-insensitive
		"NOISY.":     "noisy",  // trailing punctuation tolerated
		"Varies":     "—",      // legacy non-canonical → dash
		"per":        "—",      // umbrella packages
		"Low":        "—",      // pre-refactor wording
	}
	for in, want := range cases {
		if got := normalizeDetectionLevel(in); got != want {
			t.Errorf("normalizeDetectionLevel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAreaOf(t *testing.T) {
	cases := map[string]string{
		"crypto":            "_layer-0",
		"encode":            "_layer-0",
		"hash":              "_layer-0",
		"random":            "_layer-0",
		"useragent":         "_layer-0",
		"ui":                "_utility",
		"inject":            "inject",
		"c2/shell":          "c2",
		"evasion/amsi":      "evasion",
		"win/api":           "win",
		"kernel/driver":     "kernel",
		"recon/sandbox":     "recon",
		"process/tamper/fakecmd": "process",
	}
	for in, want := range cases {
		if got := areaOf(in); got != want {
			t.Errorf("areaOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPluralS(t *testing.T) {
	if got := pluralS(0); got != "s" {
		t.Errorf("pluralS(0) = %q", got)
	}
	if got := pluralS(1); got != "" {
		t.Errorf("pluralS(1) = %q", got)
	}
	if got := pluralS(2); got != "s" {
		t.Errorf("pluralS(2) = %q", got)
	}
}
