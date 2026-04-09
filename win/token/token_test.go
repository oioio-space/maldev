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

func TestNew(t *testing.T) {
	// New with a zero token should not panic.
	tok := New(0, Primary)
	assert.NotNil(t, tok)
	assert.Zero(t, tok.Token(), "zero token should remain zero")
}

func TestOpenProcessTokenSelf(t *testing.T) {
	tok, err := OpenProcessToken(int(windows.GetCurrentProcessId()), Primary)
	require.NoError(t, err)
	defer tok.Close()
	assert.NotZero(t, tok.Token())

	details, err := tok.UserDetails()
	require.NoError(t, err)
	assert.NotEmpty(t, details.Username)
}

func TestStealSelf(t *testing.T) {
	// Steal from own process — always works even without admin.
	tok, err := Steal(int(windows.GetCurrentProcessId()))
	require.NoError(t, err)
	defer tok.Close()
	assert.NotZero(t, tok.Token())
}

func TestDetach(t *testing.T) {
	var rawToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &rawToken)
	require.NoError(t, err, "OpenProcessToken failed")

	tok := New(rawToken, Primary)

	detached := tok.Detach()
	assert.NotZero(t, detached, "Detach must return a non-zero handle")
	assert.Zero(t, tok.Token(), "Token() must return 0 after Detach")

	// Close the detached handle manually to avoid leaking.
	windows.CloseHandle(windows.Handle(detached))
}

func TestTokenReturnsHandle(t *testing.T) {
	tok := openCurrentProcessToken(t)
	defer tok.Close()

	assert.NotZero(t, tok.Token(), "Token() must return a non-zero handle for the current process token")
}

func TestCloseIdempotent(t *testing.T) {
	tok := openCurrentProcessToken(t)

	// First close.
	tok.Close()
	assert.Zero(t, tok.Token(), "Token() must be zero after Close")

	// Second close must not panic.
	tok.Close()
	assert.Zero(t, tok.Token(), "Token() must remain zero after second Close")
}

func TestPrivilegesOnClosedToken(t *testing.T) {
	tok := openCurrentProcessToken(t)
	tok.Close()

	_, err := tok.Privileges()
	assert.ErrorIs(t, err, ErrTokenClosed)
}

func TestEnablePrivilegeOnClosedToken(t *testing.T) {
	tok := openCurrentProcessToken(t)
	tok.Close()

	err := tok.EnablePrivilege("SeShutdownPrivilege")
	assert.ErrorIs(t, err, ErrTokenClosed)
}

func TestDisablePrivilegeOnClosedToken(t *testing.T) {
	tok := openCurrentProcessToken(t)
	tok.Close()

	err := tok.DisablePrivilege("SeShutdownPrivilege")
	assert.ErrorIs(t, err, ErrTokenClosed)
}

func TestRemovePrivilegeOnClosedToken(t *testing.T) {
	tok := openCurrentProcessToken(t)
	tok.Close()

	err := tok.RemovePrivilege("SeShutdownPrivilege")
	assert.ErrorIs(t, err, ErrTokenClosed)
}

func TestEnableDisablePrivilege(t *testing.T) {
	// Open with TOKEN_ALL_ACCESS so we can adjust privileges.
	tok, err := OpenProcessToken(0, Primary)
	require.NoError(t, err)
	defer tok.Close()

	privs, err := tok.Privileges()
	require.NoError(t, err)
	require.NotEmpty(t, privs, "current process must have at least one privilege")

	// Find a privilege that exists (any will do for enable/disable round-trip).
	privName := privs[0].Name

	// Enable it (may already be enabled, that is fine).
	err = tok.EnablePrivilege(privName)
	assert.NoError(t, err, "EnablePrivilege must not fail for %s", privName)

	// Disable it.
	err = tok.DisablePrivilege(privName)
	assert.NoError(t, err, "DisablePrivilege must not fail for %s", privName)
}

func TestModifyEmptyPrivilegeList(t *testing.T) {
	tok, err := OpenProcessToken(0, Primary)
	require.NoError(t, err)
	defer tok.Close()

	assert.ErrorIs(t, tok.EnablePrivileges(nil), ErrNoPrivilegesSpecified)
	assert.ErrorIs(t, tok.DisablePrivileges(nil), ErrNoPrivilegesSpecified)
	assert.ErrorIs(t, tok.RemovePrivileges(nil), ErrNoPrivilegesSpecified)
}

func TestPrivilegeString(t *testing.T) {
	tests := []struct {
		priv Privilege
		want string
	}{
		{Privilege{Name: "SeDebugPrivilege", Enabled: true}, "SeDebugPrivilege: Enabled"},
		{Privilege{Name: "SeShutdownPrivilege", Enabled: false}, "SeShutdownPrivilege: Disabled"},
		{Privilege{Name: "SeBackupPrivilege", Removed: true}, "SeBackupPrivilege: Removed"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.priv.String())
	}
}

func TestUserDetailString(t *testing.T) {
	ud := UserDetail{
		Username:       "testuser",
		Domain:         "WORKGROUP",
		AccountType:    1,
		UserProfileDir: `C:\Users\testuser`,
	}
	s := ud.String()
	assert.Contains(t, s, "testuser")
	assert.Contains(t, s, "WORKGROUP")
}
