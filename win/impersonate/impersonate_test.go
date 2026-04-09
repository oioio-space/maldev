//go:build windows

package impersonate

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oioio-space/maldev/testutil"
)

// TestImpersonateThread impersonates a local or domain account on a locked OS
// thread, verifies the effective token owner changes, then reverts.
//
// PREREQUISITES:
//   - Valid username and password for a local or domain account
//   - Run in a VM or isolated test environment
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_TEST_USER=testuser MALDEV_TEST_PASS=testpass \
//	  go test ./win/impersonate/ -run TestImpersonateThread -v
//
//	For a domain account, also set MALDEV_TEST_DOMAIN:
//	MALDEV_MANUAL=1 MALDEV_TEST_USER=testuser MALDEV_TEST_PASS=testpass MALDEV_TEST_DOMAIN=CORP \
//	  go test ./win/impersonate/ -run TestImpersonateThread -v
//
// VERIFY:
//
//	The test logs should show the impersonated user's name and domain during
//	the callback. After the callback returns, RevertToSelf is called automatically.
//
// CLEANUP:
//
//	No persistent changes; RevertToSelf is deferred inside ImpersonateThread.
func TestImpersonateThread(t *testing.T) {
	testutil.RequireManual(t)

	user := os.Getenv("MALDEV_TEST_USER")
	pass := os.Getenv("MALDEV_TEST_PASS")
	if user == "" || pass == "" {
		t.Skip("set MALDEV_TEST_USER and MALDEV_TEST_PASS to run this test")
	}

	domain := os.Getenv("MALDEV_TEST_DOMAIN")
	isInDomain := domain != ""

	var impersonatedUser, impersonatedDomain string

	err := ImpersonateThread(isInDomain, domain, user, pass, func() error {
		var cbErr error
		impersonatedUser, impersonatedDomain, cbErr = ThreadEffectiveTokenOwner()
		return cbErr
	})
	require.NoError(t, err)

	t.Logf("impersonated as: %s\\%s", impersonatedDomain, impersonatedUser)
	assert.Equal(t, user, impersonatedUser, "effective token owner should match the supplied username")
}

// TestLogonUserW verifies that LogonUserW returns a valid token for correct
// credentials and an error for invalid ones.
//
// PREREQUISITES:
//   - Valid local account credentials
//   - Run in a VM
//
// USAGE:
//
//	MALDEV_MANUAL=1 MALDEV_TEST_USER=testuser MALDEV_TEST_PASS=testpass \
//	  go test ./win/impersonate/ -run TestLogonUserW -v
//
// CLEANUP:
//
//	The token is closed at the end of the test; no persistent changes.
func TestLogonUserW(t *testing.T) {
	testutil.RequireManual(t)

	user := os.Getenv("MALDEV_TEST_USER")
	pass := os.Getenv("MALDEV_TEST_PASS")
	if user == "" || pass == "" {
		t.Skip("set MALDEV_TEST_USER and MALDEV_TEST_PASS to run this test")
	}

	tok, err := LogonUserW(user, ".", pass, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT)
	require.NoError(t, err)
	require.NotZero(t, tok, "expected a valid token handle")
	defer tok.Close()

	t.Logf("LogonUserW returned token handle: %v", tok)

	// Verify that bogus credentials fail.
	_, badErr := LogonUserW(user, ".", "wrong_password_maldev_test", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT)
	assert.Error(t, badErr, "expected error for wrong password")
}

// TestThreadEffectiveTokenOwner reads the current thread's effective token
// owner. This is safe to run without special environment variables.
func TestThreadEffectiveTokenOwner(t *testing.T) {
	user, domain, err := ThreadEffectiveTokenOwner()
	require.NoError(t, err)
	assert.NotEmpty(t, user, "expected non-empty username")
	t.Logf("current effective token owner: %s\\%s", domain, user)
}
