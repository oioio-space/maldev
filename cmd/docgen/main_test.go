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
		"Package no period":                         "",
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
		{RelativePath: "pe/masquerade/preset/cmd"},
		{RelativePath: "pe/masquerade/internal/gen"},
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
