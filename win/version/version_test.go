//go:build windows

package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCurrent(t *testing.T) {
	v := Current()
	require.NotNil(t, v)
	assert.GreaterOrEqual(t, v.MajorVersion, uint32(10), "expected major version >= 10")
	assert.Greater(t, v.BuildNumber, uint32(0), "expected build number > 0")
}

func TestWindows(t *testing.T) {
	wv, err := Windows()
	require.NoError(t, err)
	require.NotNil(t, wv)
	assert.GreaterOrEqual(t, wv.Major, uint32(10), "expected major >= 10")
	assert.Greater(t, wv.Build, uint32(0), "expected build > 0")
	assert.NotEmpty(t, wv, "expected non-empty WindowsVersion")
}

func TestVersionString(t *testing.T) {
	v := Current()
	require.NotNil(t, v)
	s := v.String()
	assert.NotEmpty(t, s, "expected non-empty version string")
	assert.NotEqual(t, "unknown", s, "expected a known version string")
}
