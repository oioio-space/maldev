//go:build windows

package unhook

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/testutil"
)

// TestClassicUnhook_UsesProvidedOpener proves the new opener parameter
// is not ignored: a spy opener wrapping a Standard reader is consulted
// exactly once per ClassicUnhook call, with a path that points at
// System32\ntdll.dll.
func TestClassicUnhook_UsesProvidedOpener(t *testing.T) {
	testutil.RequireIntrusive(t)

	spy := &testutil.SpyOpener{}
	// NtCreateSection is safe — the Go runtime never calls it, so failing
	// to patch doesn't break later tests.
	err := ClassicUnhook("NtCreateSection", nil, spy)
	// Patching may fail in hardened environments; we care about opener use.
	if err != nil {
		t.Logf("ClassicUnhook returned %v (non-fatal for this assertion)", err)
	}
	assert.Equal(t, int32(1), spy.Calls.Load(),
		"ClassicUnhook must call Opener.Open exactly once")
	if last := spy.Last(); last != "" {
		assert.Equal(t, "ntdll.dll", filepath.Base(last),
			"Opener must be asked for ntdll.dll")
	}
}

// TestFullUnhook_UsesProvidedOpener is the FullUnhook analog.
func TestFullUnhook_UsesProvidedOpener(t *testing.T) {
	testutil.RequireIntrusive(t)

	spy := &testutil.SpyOpener{}
	_ = FullUnhook(nil, spy)
	assert.Equal(t, int32(1), spy.Calls.Load(),
		"FullUnhook must call Opener.Open exactly once")
	if last := spy.Last(); last != "" {
		assert.Equal(t, "ntdll.dll", filepath.Base(last))
	}
}

// TestClassicUnhook_WithStealthOpener exercises the real composition:
// build a Stealth opener from the actual ntdll.dll Object ID and run
// ClassicUnhook through it. On success the unhooked function must have
// the clean syscall stub prologue; path-based CreateFile hooks (if any)
// never see ntdll.dll.
func TestClassicUnhook_WithStealthOpener(t *testing.T) {
	testutil.RequireIntrusive(t)

	sysDir, _ := windows.GetSystemDirectory()
	ntdllPath := filepath.Join(sysDir, "ntdll.dll")
	stealth, err := stealthopen.NewStealth(ntdllPath)
	if err != nil {
		t.Skipf("cannot build Stealth opener for %q: %v", ntdllPath, err)
	}

	const target = "NtCreateSection"
	err = ClassicUnhook(target, nil, stealth)
	require.NoError(t, err, "ClassicUnhook with Stealth opener must succeed")
	assertCleanSyscallStub(t, target)
}
