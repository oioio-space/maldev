//go:build windows

package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	name, status, err := Name()
	require.NoError(t, err)
	assert.NotEmpty(t, name, "domain/workgroup name should not be empty")
	// Status should be one of the known values
	assert.True(t, status <= StatusDomain,
		"unexpected join status: %s (%d)", status, status)
}

func TestJoinStatusString(t *testing.T) {
	assert.Equal(t, "NetSetupUnknownStatus", StatusUnknown.String())
	assert.Equal(t, "NetSetupUnjoined", StatusUnjoined.String())
	assert.Equal(t, "NetSetupWorkgroupName", StatusWorkgroup.String())
	assert.Equal(t, "NetSetupDomainName", StatusDomain.String())
	assert.Contains(t, JoinStatus(99).String(), "99")
}
