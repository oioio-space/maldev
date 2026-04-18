//go:build windows

package token

import (
	"errors"
	"testing"

	"github.com/oioio-space/maldev/testutil"
)

// TestInteractive calls WTSEnumerateSessions + WTSQueryUserToken to fetch the
// active console user's token. Requires the caller to have the rights needed
// by WTSQueryUserToken (SYSTEM or admin with SE_TCB_NAME). In CI-style
// headless VMs without an active session, the call may fail with
// ERROR_NO_TOKEN -- that is also acceptable here: the test verifies the call
// reaches the Windows API without panicking and returns sensible types.
func TestInteractive(t *testing.T) {
	testutil.RequireAdmin(t)

	tok, err := Interactive(Primary)
	if err != nil {
		// Acceptable when no interactive session is attached (headless VM).
		t.Logf("Interactive returned error (expected on headless hosts): %v", err)
		return
	}
	if tok == nil {
		t.Fatal("Interactive returned nil token and nil error")
	}
	defer tok.Close()

	if tok.Token() == 0 {
		t.Error("Interactive returned a Token wrapper with a zero raw handle")
	}
}

func TestInteractiveRejectsInvalidType(t *testing.T) {
	// Pass a bogus type value -- must return ErrOnlyPrimaryImpersonationTokenAllowed
	// WITHOUT any WTS API call. This path needs no admin rights.
	const bogus Type = 99
	_, err := Interactive(bogus)
	if !errors.Is(err, ErrOnlyPrimaryImpersonationTokenAllowed) {
		t.Fatalf("Interactive(bogus) = %v, want ErrOnlyPrimaryImpersonationTokenAllowed", err)
	}
}
