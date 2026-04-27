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

func TestParseGuestPropertyValue(t *testing.T) {
	cases := map[string]string{
		"":                                    "",
		"No value set!\n":                     "",
		"Value: 192.168.56.103\n":             "192.168.56.103",
		"  Value: 10.0.2.15  ":                "10.0.2.15",
		"Value:\t192.168.56.103":              "192.168.56.103",
		"Last changed: 2026-04-27T08:00:00Z":  "",
	}
	for in, want := range cases {
		if got := parseGuestPropertyValue([]byte(in)); got != want {
			t.Errorf("parseGuestPropertyValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRemoteCleanCmd(t *testing.T) {
	if got := remoteCleanCmd("linux", "/tmp/maldev"); !strings.Contains(got, "rm -rf /tmp/maldev") || !strings.Contains(got, "mkdir -p /tmp/maldev") {
		t.Errorf("linux cleanCmd missing rm/mkdir: %q", got)
	}
	got := remoteCleanCmd("windows", `C:\maldev`)
	if !strings.Contains(got, "rmdir /s /q") || !strings.Contains(got, "mkdir") || !strings.Contains(got, "cmd.exe /c") {
		t.Errorf("windows cleanCmd missing rmdir/mkdir/cmd.exe: %q", got)
	}
}

func TestRemoteExtractCmd(t *testing.T) {
	if got := remoteExtractCmd("linux", "/tmp/maldev"); got != "tar -xzf - -C /tmp/maldev" {
		t.Errorf("linux extract = %q", got)
	}
	if got := remoteExtractCmd("windows", `C:\maldev`); !strings.Contains(got, "tar -xzf -") || !strings.Contains(got, `C:\maldev`) {
		t.Errorf("windows extract = %q", got)
	}
}

func TestRemoteGoTest(t *testing.T) {
	envs := []string{"MALDEV_INTRUSIVE=1", "MALDEV_MANUAL=1"}

	got, err := remoteGoTest("linux", "/tmp/maldev", "./...", "-count=1", envs)
	if err != nil {
		t.Fatalf("linux: %v", err)
	}
	for _, want := range []string{"cd /tmp/maldev", "MALDEV_INTRUSIVE=1", "MALDEV_MANUAL=1", "go test ./... -count=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("linux missing %q in %q", want, got)
		}
	}

	got, err = remoteGoTest("windows", `C:\maldev`, "./...", "-count=1", envs)
	if err != nil {
		t.Fatalf("windows: %v", err)
	}
	for _, want := range []string{"cmd.exe /c", "cd /d C:\\maldev", "set MALDEV_INTRUSIVE=1", "set MALDEV_MANUAL=1", "go test ./... -count=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("windows missing %q in %q", want, got)
		}
	}

	if _, err := remoteGoTest("darwin", "/tmp", "./...", "", nil); err == nil {
		t.Errorf("expected error for unsupported platform")
	}

	got, _ = remoteGoTest("linux", "/tmp/x", "./...", "", nil)
	if strings.Contains(got, "  ") {
		t.Errorf("empty envs should not introduce double-space: %q", got)
	}
}
