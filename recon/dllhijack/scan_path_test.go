package dllhijack

import (
	"reflect"
	"testing"
)

func TestSplitPath(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{`C:\Windows\system32`, []string{`C:\Windows\system32`}},
		{
			`C:\Windows\system32;C:\Windows;C:\Tools`,
			[]string{`C:\Windows\system32`, `C:\Windows`, `C:\Tools`},
		},
		// Empty segments + whitespace + quoted entries (installers
		// occasionally write these into the registry verbatim).
		{
			`C:\A;;  C:\B  ;"C:\Program Files\X"`,
			[]string{`C:\A`, `C:\B`, `C:\Program Files\X`},
		},
	}
	for _, c := range cases {
		got := splitPath(c.raw)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitPath(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// TestMergePathSources_SystemFirst proves the merged slice preserves
// the system-hive ordering and de-dupes (case-insensitive) so a dir
// present in both hives is reported once with FromSystem=true.
func TestMergePathSources_SystemFirst(t *testing.T) {
	got := mergePathSources(
		`C:\Windows\system32;C:\Tools\Sys`,
		`C:\Users\bob\bin;C:\TOOLS\sys`, // overlap in different case
	)
	want := []pathEntry{
		{Dir: `C:\Windows\system32`, FromSystem: true},
		{Dir: `C:\Tools\Sys`, FromSystem: true},
		{Dir: `C:\Users\bob\bin`, FromSystem: false},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("mergePathSources mismatch:\n got %v\nwant %v", got, want)
	}
}

func TestMergePathSources_EmptyUserHive(t *testing.T) {
	got := mergePathSources(`C:\Windows\system32`, "")
	want := []pathEntry{{Dir: `C:\Windows\system32`, FromSystem: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestKindPathHijack_String pins the human-readable label so callers
// formatting Opportunity rows (operator UIs, log lines) don't break
// silently when new Kinds are added.
func TestKindPathHijack_String(t *testing.T) {
	if got := KindPathHijack.String(); got != "path-hijack" {
		t.Errorf("got %q, want %q", got, "path-hijack")
	}
}

// TestRank_PathHijackOrdering asserts the Rank() weights place a
// system-PATH writable dir close to but below a SYSTEM service hit,
// and well above a user-PATH dir.
func TestRank_PathHijackOrdering(t *testing.T) {
	in := []Opportunity{
		{Kind: KindPathHijack, ID: "user-dir", IntegrityGain: false},   // 40 + 0 = 40
		{Kind: KindPathHijack, ID: "system-dir", IntegrityGain: true},  // 40 + 100 = 140
		{Kind: KindService, ID: "svc", IntegrityGain: true},            // 50 + 100 = 150
		{Kind: KindScheduledTask, ID: "task", IntegrityGain: false},    // 20
	}
	ranked := Rank(in)
	// svc=150 > system-dir=140 > user-dir=40 > task=20 — confirms
	// the new KindPathHijack weight sits between Service and
	// ScheduledTask, with IntegrityGain still the dominant factor.
	wantOrder := []string{"svc", "system-dir", "user-dir", "task"}
	got := make([]string, len(ranked))
	for i, o := range ranked {
		got[i] = o.ID
	}
	if !reflect.DeepEqual(got, wantOrder) {
		t.Errorf("ranking mismatch:\n got %v\nwant %v", got, wantOrder)
	}
}
