//go:build windows

package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func openCurrentProcessToken(t *testing.T) *Token {
	t.Helper()
	var rawToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &rawToken)
	require.NoError(t, err, "OpenProcessToken failed")
	return New(rawToken, Primary)
}

func TestOpenCurrentProcessToken(t *testing.T) {
	tok := openCurrentProcessToken(t)
	require.NotNil(t, tok)
	tok.Close()
}

func TestTokenPrivileges(t *testing.T) {
	tok := openCurrentProcessToken(t)
	defer tok.Close()

	privs, err := tok.Privileges()
	require.NoError(t, err)
	assert.NotEmpty(t, privs, "expected at least one privilege on the current process token")
}

func TestTokenUserDetails(t *testing.T) {
	tok := openCurrentProcessToken(t)
	defer tok.Close()

	details, err := tok.UserDetails()
	require.NoError(t, err)
	assert.NotEmpty(t, details.Username, "expected non-empty Username in token user details")
}

func TestTokenIntegrityLevel(t *testing.T) {
	tok := openCurrentProcessToken(t)
	defer tok.Close()

	level, err := tok.IntegrityLevel()
	require.NoError(t, err)
	assert.NotEmpty(t, level, "expected non-empty integrity level string")
}
