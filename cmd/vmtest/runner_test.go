package main

import (
	"strings"
	"testing"
)

func TestInjectCoverprofile(t *testing.T) {
	cases := []struct {
		name   string
		flags  string
		path   string
		wants  []string // substrings expected in result
		absent []string // substrings expected NOT in result
	}{
		{
			name:  "empty flags",
			flags: "",
			path:  "/tmp/c.out",
			wants: []string{"-coverprofile=/tmp/c.out", "-covermode=atomic"},
		},
		{
			name:  "preserves user flags",
			flags: "-v -count=1",
			path:  "/tmp/c.out",
			wants: []string{"-v", "-count=1", "-coverprofile=/tmp/c.out", "-covermode=atomic"},
		},
		{
			name:   "user-supplied coverprofile wins",
			flags:  "-coverprofile=mine.out",
			path:   "/tmp/c.out",
			wants:  []string{"-coverprofile=mine.out", "-covermode=atomic"},
			absent: []string{"-coverprofile=/tmp/c.out"},
		},
		{
			name:   "user-supplied covermode wins",
			flags:  "-covermode=count",
			path:   "/tmp/c.out",
			wants:  []string{"-coverprofile=/tmp/c.out", "-covermode=count"},
			absent: []string{"-covermode=atomic"},
		},
		{
			name:   "both set -> no injection",
			flags:  "-coverprofile=x -covermode=set",
			path:   "/tmp/c.out",
			wants:  []string{"-coverprofile=x", "-covermode=set"},
			absent: []string{"-coverprofile=/tmp/c.out", "-covermode=atomic"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := injectCoverprofile(tc.flags, tc.path)
			for _, want := range tc.wants {
				if !strings.Contains(got, want) {
					t.Errorf("want %q in %q", want, got)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(got, absent) {
					t.Errorf("did not expect %q in %q", absent, got)
				}
			}
		})
	}
}

func TestSafeLabel(t *testing.T) {
	cases := map[string]string{
		"":             "vm",
		"win10":        "win10",
		"ubuntu20.04-": "ubuntu20.04-",
		"vm/with/slash": "vm_with_slash",
		"a\\b":         "a_b",
		"foo:bar":      "foo_bar",
		"with space":   "with_space",
	}
	for in, want := range cases {
		if got := safeLabel(in); got != want {
			t.Errorf("safeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGuestCoverPath(t *testing.T) {
	if got := guestCoverPath("windows"); !strings.HasPrefix(got, "C:/") {
		t.Errorf("windows path should start with C:/, got %q", got)
	}
	if got := guestCoverPath("linux"); !strings.HasPrefix(got, "/tmp/") {
		t.Errorf("linux path should start with /tmp/, got %q", got)
	}
	// Unknown platforms fall through to the linux branch — acceptable default.
	if got := guestCoverPath("darwin"); !strings.HasPrefix(got, "/tmp/") {
		t.Errorf("unknown platform should fall back to /tmp/, got %q", got)
	}
}

func TestGuestClrhostCoverPath(t *testing.T) {
	if got := guestClrhostCoverPath("windows"); got == "" || !strings.Contains(got, "clrhost-cover.out") {
		t.Errorf("windows clrhost path missing or malformed: %q", got)
	}
	// Non-Windows: CLR is Windows-only, empty string disables the fetch.
	if got := guestClrhostCoverPath("linux"); got != "" {
		t.Errorf("linux clrhost path should be empty, got %q", got)
	}
	if got := guestClrhostCoverPath("darwin"); got != "" {
		t.Errorf("darwin clrhost path should be empty, got %q", got)
	}
}
