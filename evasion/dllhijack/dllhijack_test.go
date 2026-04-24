package dllhijack

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKindString(t *testing.T) {
	cases := map[Kind]string{
		KindService:       "service",
		KindProcess:       "process",
		KindScheduledTask: "scheduled-task",
		Kind(0):           "unknown",
		Kind(99):          "unknown",
	}
	for k, want := range cases {
		assert.Equal(t, want, k.String(), "Kind(%d)", int(k))
	}
}

func TestParseBinaryPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"   ", ""},
		{`C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted`, `C:\Windows\System32\svchost.exe`},
		{`"C:\Program Files\MyService\svc.exe" --arg`, `C:\Program Files\MyService\svc.exe`},
		{`C:\Windows\System32\drivers\foo.sys`, `C:\Windows\System32\drivers\foo.sys`}, // no args
		{`   C:\svc.exe    -a -b -c`, `C:\svc.exe`},                                    // leading space, trimmed
		{`"C:\unterminated`, ""},                                                       // malformed quote
		{`"C:\bin.exe"`, `C:\bin.exe`},                                                 // quoted, no args
	}
	for _, c := range cases {
		got := ParseBinaryPath(c.in)
		assert.Equal(t, c.want, got, "in=%q", c.in)
	}
}
