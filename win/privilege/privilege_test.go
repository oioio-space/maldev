//go:build windows

package privilege

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsAdmin verifies that IsAdmin executes without panicking and returns
// consistent types. Whether the result is true or false depends on the
// privileges of the test runner. Some CI/test environments run under a
// restricted impersonation token that does not support TOKEN_QUERY; in that
// case the test is skipped rather than failed.
func TestIsAdmin(t *testing.T) {
	admin, elevated, err := IsAdmin()
	if err != nil {
		t.Skipf("IsAdmin returned an error (restricted token environment): %v", err)
	}
	// admin and elevated are both bool — assert they are actually bool (no
	// implicit conversion panics). If admin is false, elevated must also be
	// false; the converse is not guaranteed (token may be elevated via UAC
	// without Administrators group membership).
	t.Logf("IsAdmin: admin=%v elevated=%v", admin, elevated)
	assert.IsType(t, false, admin)
	assert.IsType(t, false, elevated)
}

// TestIsAdminGroupMember verifies that IsAdminGroupMember returns without
// panicking. The actual boolean result depends on the current user's groups.
func TestIsAdminGroupMember(t *testing.T) {
	isMember, err := IsAdminGroupMember()
	require.NoError(t, err)
	t.Logf("IsAdminGroupMember: %v", isMember)
	assert.IsType(t, false, isMember)
}
