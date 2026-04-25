//go:build windows

package antivm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectNicNoFalsePositive(t *testing.T) {
	// The broadcast MAC FF:FF:FF is never assigned to a real NIC, so
	// DetectNic must return found=false when given that prefix.
	found, mac, err := DetectNic([]string{"FF:FF:FF"})
	require.NoError(t, err)
	assert.False(t, found, "DetectNic should not match broadcast MAC FF:FF:FF (got %q)", mac)
}

func TestDetectNicEmptyList(t *testing.T) {
	// An empty prefix list matches nothing by definition.
	found, _, err := DetectNic([]string{})
	require.NoError(t, err)
	assert.False(t, found, "DetectNic with empty prefix list must return found=false")
}
