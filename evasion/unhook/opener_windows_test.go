//go:build windows

package unhook

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/evasion/stealthopen"
	"github.com/oioio-space/maldev/testutil"
)

// spyOpener wraps a real Opener and counts Open calls, letting us assert
// that ClassicUnhook/FullUnhook routed the ntdll read through the passed
// opener instead of bypassing it.
type spyOpener struct {
	inner stealthopen.Opener
	calls atomic.Int32
	last  atomic.Pointer[string]
}

func (s *spyOpener) Open(path string) (*os.File, error) {
	s.calls.Add(1)
	s.last.Store(&path)
	if s.inner == nil {
		s.inner = &stealthopen.Standard{}
	}
	return s.inner.Open(path)
}

// TestClassicUnhook_UsesProvidedOpener proves the new opener parameter
// is not ignored: a spy opener wrapping a Standard reader is consulted
// exactly once per ClassicUnhook call, with a path that points at
// System32\ntdll.dll.
func TestClassicUnhook_UsesProvidedOpener(t *testing.T) {
	testutil.RequireIntrusive(t)

	spy := &spyOpener{}
	// NtCreateSection is safe — the Go runtime never calls it, so failing
	// to patch doesn't break later tests.
	err := ClassicUnhook("NtCreateSection", nil, spy)
	// Patching may fail in hardened environments; we care about opener use.
	if err != nil {
		t.Logf("ClassicUnhook returned %v (non-fatal for this assertion)", err)
	}
	assert.Equal(t, int32(1), spy.calls.Load(),
		"ClassicUnhook must call Opener.Open exactly once")
	if p := spy.last.Load(); p != nil {
		assert.Equal(t, "ntdll.dll", filepath.Base(*p),
			"Opener must be asked for ntdll.dll")
	}
}

// TestFullUnhook_UsesProvidedOpener is the FullUnhook analog.
func TestFullUnhook_UsesProvidedOpener(t *testing.T) {
	testutil.RequireIntrusive(t)

	spy := &spyOpener{}
	_ = FullUnhook(nil, spy)
	assert.Equal(t, int32(1), spy.calls.Load(),
		"FullUnhook must call Opener.Open exactly once")
	if p := spy.last.Load(); p != nil {
		assert.Equal(t, "ntdll.dll", filepath.Base(*p))
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
