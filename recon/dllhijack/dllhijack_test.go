package dllhijack

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKindString(t *testing.T) {
	cases := map[Kind]string{
		KindService:       "service",
		KindProcess:       "process",
		KindScheduledTask: "scheduled-task",
		KindAutoElevate:   "auto-elevate",
		Kind(0):           "unknown",
		Kind(99):          "unknown",
	}
	for k, want := range cases {
		assert.Equal(t, want, k.String(), "Kind(%d)", int(k))
	}
}

func TestIsAutoElevate(t *testing.T) {
	// Positive: element form
	pe := []byte(`...<autoElevate>true</autoElevate>...`)
	assert.True(t, IsAutoElevate(pe))

	// Positive: attribute form + case-insensitive
	pe = []byte(`<requestedExecutionLevel level="highestAvailable" autoElevate="true" uiAccess="false" />`)
	assert.True(t, IsAutoElevate(pe))

	// Positive: uppercase mixed
	pe = []byte(`<AUTOELEVATE>True</AUTOELEVATE>`)
	assert.True(t, IsAutoElevate(pe))

	// Negative: autoElevate=false
	pe = []byte(`<autoElevate>false</autoElevate>`)
	assert.False(t, IsAutoElevate(pe))

	// Negative: no autoElevate element
	pe = []byte(`<?xml version="1.0"?><assembly></assembly>`)
	assert.False(t, IsAutoElevate(pe))

	// Negative: empty
	assert.False(t, IsAutoElevate(nil))
	assert.False(t, IsAutoElevate([]byte{}))
}

func TestRank_EmptyAndTies(t *testing.T) {
	// Empty slice: must not panic, returns a new empty slice.
	out := Rank(nil)
	assert.NotNil(t, out)
	assert.Empty(t, out)
	out = Rank([]Opportunity{})
	assert.Empty(t, out)

	// Tied scores: tie-break is alphabetical on (BinaryPath, HijackedDLL).
	in := []Opportunity{
		{Kind: KindService, BinaryPath: "z.exe", HijackedDLL: "aaa.dll"},
		{Kind: KindService, BinaryPath: "a.exe", HijackedDLL: "zzz.dll"},
		{Kind: KindService, BinaryPath: "a.exe", HijackedDLL: "aaa.dll"},
	}
	out = Rank(in)
	require.Len(t, out, 3)
	assert.Equal(t, "a.exe", out[0].BinaryPath)
	assert.Equal(t, "aaa.dll", out[0].HijackedDLL)
	assert.Equal(t, "a.exe", out[1].BinaryPath)
	assert.Equal(t, "zzz.dll", out[1].HijackedDLL)
	assert.Equal(t, "z.exe", out[2].BinaryPath)
}

func TestRank(t *testing.T) {
	in := []Opportunity{
		{Kind: KindProcess, BinaryPath: "a.exe", HijackedDLL: "foo.dll"},
		{Kind: KindService, BinaryPath: "svc.exe", HijackedDLL: "bar.dll", IntegrityGain: true},
		{Kind: KindAutoElevate, BinaryPath: "fodhelper.exe", HijackedDLL: "version.dll", AutoElevate: true, IntegrityGain: true},
		{Kind: KindScheduledTask, BinaryPath: "t.exe", HijackedDLL: "baz.dll"},
	}
	out := Rank(in)
	require.Len(t, out, 4)

	// Auto-elevate first (AutoElevate + IntegrityGain + KindAutoElevate)
	assert.Equal(t, KindAutoElevate, out[0].Kind)
	assert.Equal(t, 310, out[0].Score, "200 (AutoElevate) + 100 (IntegrityGain) + 10 (KindAutoElevate)")

	// Service with IntegrityGain second
	assert.Equal(t, KindService, out[1].Kind)
	assert.Equal(t, 150, out[1].Score, "100 (IntegrityGain) + 50 (KindService)")

	// Scheduled task third
	assert.Equal(t, KindScheduledTask, out[2].Kind)

	// Process last
	assert.Equal(t, KindProcess, out[3].Kind)
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
