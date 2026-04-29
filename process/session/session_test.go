//go:build windows

package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/oioio-space/maldev/win/impersonate"
	"github.com/oioio-space/maldev/win/token"
)

// openCurrentProcessToken returns a Token wrapping the current process token.
// The caller must close it.
func openCurrentProcessToken(t *testing.T) *token.Token {
	t.Helper()
	var rawToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE, &rawToken)
	require.NoError(t, err, "OpenProcessToken failed")
	return token.New(rawToken, token.Primary)
}

// TestImpersonateThreadOnActiveSession runs the callback under the current
// process token on a locked OS thread. This is a read-only smoke test that
// requires no elevated privileges and produces no side effects.
//
// The test verifies that:
//  1. ImpersonateThreadOnActiveSession invokes the callback without error.
//  2. The effective token owner inside the callback is non-empty (the current user).
func TestImpersonateThreadOnActiveSession(t *testing.T) {
	tok := openCurrentProcessToken(t)
	defer tok.Close()

	var capturedUser, capturedDomain string

	err := ImpersonateThreadOnActiveSession(tok, func() error {
		var cbErr error
		capturedUser, capturedDomain, cbErr = impersonate.ThreadEffectiveTokenOwner()
		return cbErr
	})
	require.NoError(t, err)

	t.Logf("effective token owner during impersonation: %s\\%s", capturedDomain, capturedUser)
	assert.NotEmpty(t, capturedUser, "expected a non-empty username from the effective token")
}

// TestOptions_DesktopFieldTypeCheck is a compile-time guard so the
// Options.Desktop field doesn't drift type or get renamed without
// callers noticing.
func TestOptions_DesktopFieldTypeCheck(t *testing.T) {
	var opts Options
	opts.Desktop = `Winsta0\Default`
	if opts.Desktop != `Winsta0\Default` {
		t.Errorf("Desktop = %q, want round-trip", opts.Desktop)
	}
}

// TestCreateProcessOnActiveSessionsWith_NilOptionsLegacy compiles a
// call site equivalent to the legacy entry point so any signature
// drift on CreateProcessOnActiveSessionsWith breaks the build, not
// just the runtime.
func TestCreateProcessOnActiveSessionsWith_NilOptionsLegacy(t *testing.T) {
	// Compile-only — running it would need a user token; nil triggers
	// a nil-pointer deref before the SCM call we're guarding the API
	// shape against.
	_ = func(tok *token.Token) error {
		return CreateProcessOnActiveSessionsWith(tok, "x", nil, Options{})
	}
}
